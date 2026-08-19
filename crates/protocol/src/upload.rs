//! Transport-independent validation for the file-upload wire messages.

use crate::pb::{BeginUpload, UploadChunk};
use crate::{
    UPLOAD_CHUNK_BYTES_MAX, UPLOAD_FILE_BYTES_HARD_MAX, UPLOAD_ID_BYTES,
    UPLOAD_ORIGINAL_NAME_BYTES_MAX, UPLOAD_SHA256_BYTES,
};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UploadValidationError {
    #[error("original filename exceeds {UPLOAD_ORIGINAL_NAME_BYTES_MAX} UTF-8 bytes")]
    OriginalNameTooLong,
    #[error("upload digest must be exactly {UPLOAD_SHA256_BYTES} bytes")]
    InvalidDigest,
    #[error("declared upload length {declared} exceeds limit {maximum}")]
    FileTooLarge { declared: u64, maximum: u64 },
    #[error("upload id must be exactly {UPLOAD_ID_BYTES} bytes")]
    InvalidUploadId,
    #[error("upload chunk must not be empty")]
    EmptyChunk,
    #[error("upload chunk length {actual} exceeds limit {maximum}")]
    ChunkTooLarge { actual: usize, maximum: usize },
    #[error("upload chunk offset {actual} does not match expected offset {expected}")]
    UnexpectedOffset { actual: u64, expected: u64 },
    #[error("upload chunk would exceed the declared file length")]
    ExceedsDeclaredLength,
}

/// Validate metadata before a destination is created or any file-sized buffer
/// could be allocated. Operator configuration can only narrow the hard limit.
pub fn validate_begin(
    begin: &BeginUpload,
    configured_max_file_bytes: u64,
) -> Result<(), UploadValidationError> {
    if begin.original_name.len() > UPLOAD_ORIGINAL_NAME_BYTES_MAX {
        return Err(UploadValidationError::OriginalNameTooLong);
    }
    if begin.sha256.len() != UPLOAD_SHA256_BYTES {
        return Err(UploadValidationError::InvalidDigest);
    }
    let maximum = configured_max_file_bytes.min(UPLOAD_FILE_BYTES_HARD_MAX);
    if begin.total_bytes > maximum {
        return Err(UploadValidationError::FileTooLarge {
            declared: begin.total_bytes,
            maximum,
        });
    }
    Ok(())
}

/// Validate one ordered chunk before writing it. `maximum_chunk_bytes` is the
/// server-selected value from `UploadAccepted`; the protocol ceiling still
/// applies if a caller supplies a larger value by mistake.
pub fn validate_chunk(
    chunk: &UploadChunk,
    expected_upload_id: &[u8; UPLOAD_ID_BYTES],
    expected_offset: u64,
    maximum_chunk_bytes: u32,
    total_bytes: u64,
) -> Result<(), UploadValidationError> {
    if chunk.upload_id.len() != UPLOAD_ID_BYTES || chunk.upload_id.as_slice() != expected_upload_id
    {
        return Err(UploadValidationError::InvalidUploadId);
    }
    if chunk.data.is_empty() {
        return Err(UploadValidationError::EmptyChunk);
    }
    let maximum = usize::try_from(maximum_chunk_bytes)
        .unwrap_or(usize::MAX)
        .min(UPLOAD_CHUNK_BYTES_MAX);
    if chunk.data.len() > maximum {
        return Err(UploadValidationError::ChunkTooLarge {
            actual: chunk.data.len(),
            maximum,
        });
    }
    if chunk.offset != expected_offset {
        return Err(UploadValidationError::UnexpectedOffset {
            actual: chunk.offset,
            expected: expected_offset,
        });
    }
    let Some(end) = expected_offset.checked_add(chunk.data.len() as u64) else {
        return Err(UploadValidationError::ExceedsDeclaredLength);
    };
    if end > total_bytes {
        return Err(UploadValidationError::ExceedsDeclaredLength);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::*;
    use crate::pb::{envelope, BeginUpload, Envelope};
    use crate::{FRAME_BYTES_DEFAULT, UPLOAD_FILE_BYTES_DEFAULT};

    fn begin() -> BeginUpload {
        BeginUpload {
            original_name: "archive.tar.zst".into(),
            total_bytes: 12,
            sha256: vec![0x42; UPLOAD_SHA256_BYTES],
        }
    }

    #[test]
    fn begin_upload_round_trips_through_the_envelope() {
        let envelope = Envelope {
            request_id: 7,
            server_id: Vec::new(),
            shell_id: vec![0x11; 16],
            message: Some(envelope::Message::BeginUpload(begin())),
        };
        let encoded = envelope.encode_to_vec();
        let decoded = Envelope::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn begin_validation_enforces_digest_name_and_hard_size_bounds() {
        validate_begin(&begin(), UPLOAD_FILE_BYTES_DEFAULT).unwrap();

        let mut bad = begin();
        bad.sha256.pop();
        assert_eq!(
            validate_begin(&bad, UPLOAD_FILE_BYTES_DEFAULT),
            Err(UploadValidationError::InvalidDigest)
        );

        let mut bad = begin();
        bad.original_name = "x".repeat(UPLOAD_ORIGINAL_NAME_BYTES_MAX + 1);
        assert_eq!(
            validate_begin(&bad, UPLOAD_FILE_BYTES_DEFAULT),
            Err(UploadValidationError::OriginalNameTooLong)
        );

        let mut bad = begin();
        bad.total_bytes = UPLOAD_FILE_BYTES_HARD_MAX + 1;
        assert!(matches!(
            validate_begin(&bad, u64::MAX),
            Err(UploadValidationError::FileTooLarge { .. })
        ));
    }

    #[test]
    fn chunk_validation_rejects_oversize_before_write() {
        let upload_id = [0x55; UPLOAD_ID_BYTES];
        let chunk = UploadChunk {
            upload_id: upload_id.to_vec(),
            offset: 0,
            data: vec![0; UPLOAD_CHUNK_BYTES_MAX + 1],
        };
        assert_eq!(
            validate_chunk(
                &chunk,
                &upload_id,
                0,
                UPLOAD_CHUNK_BYTES_MAX as u32,
                (UPLOAD_CHUNK_BYTES_MAX + 1) as u64,
            ),
            Err(UploadValidationError::ChunkTooLarge {
                actual: UPLOAD_CHUNK_BYTES_MAX + 1,
                maximum: UPLOAD_CHUNK_BYTES_MAX,
            })
        );
    }

    #[test]
    fn maximum_chunk_envelope_fits_the_default_frame_bound() {
        let envelope = Envelope {
            request_id: 0,
            server_id: Vec::new(),
            shell_id: vec![0x11; 16],
            message: Some(envelope::Message::UploadChunk(UploadChunk {
                upload_id: vec![0x55; UPLOAD_ID_BYTES],
                offset: 0,
                data: vec![0; UPLOAD_CHUNK_BYTES_MAX],
            })),
        };
        assert!(envelope.encoded_len() < FRAME_BYTES_DEFAULT as usize);
    }
}

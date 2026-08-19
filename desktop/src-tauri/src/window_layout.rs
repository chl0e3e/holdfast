#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Size {
    pub(crate) width: u32,
    pub(crate) height: u32,
}

/// Return the largest inner size that keeps the decorated window inside the
/// monitor's work area. Tauri's configured width/height describe the inner
/// webview, while Windows reserves the work area for the whole decorated
/// window; on a 768px-tall display, a 720px webview plus its title bar can
/// otherwise extend behind the taskbar.
pub(crate) fn clamp_inner_to_work_area(inner: Size, outer: Size, work_area: Size) -> Size {
    let frame_width = outer.width.saturating_sub(inner.width);
    let frame_height = outer.height.saturating_sub(inner.height);

    Size {
        width: inner.width.min(work_area.width.saturating_sub(frame_width)),
        height: inner
            .height
            .min(work_area.height.saturating_sub(frame_height)),
    }
}

#[cfg(test)]
mod tests {
    use super::{clamp_inner_to_work_area, Size};

    #[test]
    fn preserves_a_window_that_already_fits() {
        let inner = Size {
            width: 1100,
            height: 720,
        };
        assert_eq!(
            clamp_inner_to_work_area(
                inner,
                Size {
                    width: 1116,
                    height: 759,
                },
                Size {
                    width: 1920,
                    height: 1040,
                },
            ),
            inner
        );
    }

    #[test]
    fn reserves_room_for_windows_chrome_above_the_taskbar() {
        assert_eq!(
            clamp_inner_to_work_area(
                Size {
                    width: 1100,
                    height: 720,
                },
                Size {
                    width: 1116,
                    height: 759,
                },
                Size {
                    width: 1366,
                    height: 720,
                },
            ),
            Size {
                width: 1100,
                height: 681,
            }
        );
    }

    #[test]
    fn clamps_both_dimensions_on_a_small_work_area() {
        assert_eq!(
            clamp_inner_to_work_area(
                Size {
                    width: 1100,
                    height: 720,
                },
                Size {
                    width: 1116,
                    height: 759,
                },
                Size {
                    width: 1024,
                    height: 700,
                },
            ),
            Size {
                width: 1008,
                height: 661,
            }
        );
    }
}

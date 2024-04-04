use libseccomp_sys::{
    seccomp_notif, seccomp_notif_resp, seccomp_notify_alloc, seccomp_notify_free,
    seccomp_notify_id_valid, seccomp_notify_receive, seccomp_notify_respond,
    SECCOMP_USER_NOTIF_FLAG_CONTINUE,
};
use std::fs::{File, OpenOptions};
use std::io;
use std::io::ErrorKind;
use std::os::fd::{AsRawFd, RawFd};
use std::os::raw::c_int;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio_stream::Stream;

pub use syscalls::Sysno;

#[cfg(not(target_os = "linux"))]
compile_error!("There is little to no point to run this crate on non-Linux systems!");

/// Represents a notification from the seccomp system call.
///
/// This struct contains information about a system call that has been intercepted by seccomp.
/// It includes the system call number (`syscall`), the arguments to the system call (`args`),
/// and other relevant information such as the process ID (`pid`) and a file descriptor (`fd`).
#[derive(Debug, Copy, Clone)]
pub struct Notification {
    /// The unique identifier for the notification.
    id: u64,
    /// The process ID that made the system call.
    pid: u32,
    /// The system call number.
    pub syscall: crate::Sysno,
    /// The arguments to the system call.
    pub args: [u64; 6],
    /// A file descriptor associated with the notification.
    fd: RawFd,
}

/// Represents the type of response to a seccomp notification.
///
/// This enum is used to specify the outcome of handling a seccomp notification.
/// It can indicate success with a return value, a raw error code, or an `io::Error` for convenience.
pub enum ResponseType {
    /// Indicates success with a specific return value.
    Success(i64),
    /// Indicates an error that will be written to the targets errno.
    RawError(i32),
    /// Indicates an error with an `io::Error`. It will be converted to an integer and written to the targets errno.
    Error(io::Error),
}

/// Converts a raw error code to a `Result`.
///
/// This function takes a raw error code (as an `c_int`) and converts it to a `Result`.
/// If the error code is 0, it returns `Ok(())`. Otherwise, it converts the error code
/// to an `io::Error` and returns `Err(io::Error)`.
fn cvt(result: c_int) -> Result<(), io::Error> {
    match result {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

/// Represents a raw seccomp notification.
///
/// This struct wraps a raw pointer to a `seccomp_notif` structure.
/// It is used to manage the memory of the seccomp notification.
///
/// You should *probably* not be using this directly
#[derive(Debug)]
struct RawNotification(*mut seccomp_notif);

impl Drop for RawNotification {
    /// Frees the memory associated with the raw seccomp notification.
    ///
    /// This method is called when a `RawNotification` is dropped.
    /// It ensures that the memory allocated for the `seccomp_notif` structure is properly freed.
    fn drop(&mut self) {
        let ptr = std::mem::replace(&mut self.0, std::ptr::null_mut());
        if !ptr.is_null() {
            unsafe {
                seccomp_notify_free(ptr, std::ptr::null_mut());
            }
        }
    }
}

/// Represents a raw seccomp response.
///
/// This struct wraps a raw pointer to a `seccomp_notif_resp` structure.
/// It is used to manage the memory of the seccomp response.
///
/// You should *probably* not be using this directly
#[derive(Debug)]
struct RawResponse(*mut seccomp_notif_resp);

impl Drop for RawResponse {
    /// Frees the memory associated with the raw seccomp response.
    ///
    /// This method is called when a `RawResponse` is dropped.
    /// It ensures that the memory allocated for the `seccomp_notif_resp` structure is properly freed.
    fn drop(&mut self) {
        let ptr = std::mem::replace(&mut self.0, std::ptr::null_mut());
        if !ptr.is_null() {
            unsafe {
                seccomp_notify_free(std::ptr::null_mut(), ptr);
            }
        }
    }
}

impl RawResponse {
    /// Allocates a new raw seccomp response.
    ///
    /// This method allocates memory for a `seccomp_notif_resp` structure and returns a `RawResponse`
    /// that wraps the pointer to this structure.
    pub fn new() -> Result<Self, io::Error> {
        let mut response = std::ptr::null_mut();

        cvt(unsafe { seccomp_notify_alloc(std::ptr::null_mut(), &mut response) })?;

        Ok(Self(response))
    }

    /// Sends a continue response for a seccomp notification.
    ///
    /// This method sets the response to continue the execution of the intercepted system call
    /// and sends the response back to the kernel.
    ///
    /// # Safety
    ///
    /// This method is unsafe because continuing a syscall is inherently unsafe.
    /// Please consult the notes on
    /// [SECCOMP_USER_NOTIF_FLAG_CONTINUE in man seccomp_unotify(2)](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html#NOTES)
    pub unsafe fn send_continue(self, fd: RawFd, id: u64) -> Result<(), io::Error> {
        (*self.0).id = id;
        (*self.0).val = 0;
        (*self.0).error = 0;

        (*self.0).flags |= SECCOMP_USER_NOTIF_FLAG_CONTINUE;

        cvt(unsafe { seccomp_notify_respond(fd, self.0) })?;
        Ok(())
    }

    /// Sends a response for a seccomp notification.
    ///
    /// This method sets the response based on the provided `ResponseType` and sends the response
    /// back to the kernel.
    pub fn send(self, fd: RawFd, id: u64, response_type: ResponseType) -> Result<(), io::Error> {
        unsafe {
            (*self.0).id = id;
        }

        match response_type {
            ResponseType::Success(val) => unsafe {
                (*self.0).val = val;
                (*self.0).error = 0;
            },
            ResponseType::RawError(err) => unsafe {
                (*self.0).val = 0;
                (*self.0).error = err;
            },
            ResponseType::Error(err) => unsafe {
                (*self.0).val = 0;
                (*self.0).error = err.raw_os_error().ok_or_else(|| {
                    io::Error::new(
                        ErrorKind::InvalidData,
                        "Supplied io::Error did not map to an OS error!",
                    )
                })?;
            },
        }

        cvt(unsafe { seccomp_notify_respond(fd, self.0) })?;
        Ok(())
    }
}

impl RawNotification {
    /// Allocates a new raw seccomp notification.
    ///
    /// This method allocates memory for a `seccomp_notif` structure and returns a `RawNotification`
    /// that wraps the pointer to this structure.
    pub fn new() -> Result<Self, io::Error> {
        let mut notification = std::ptr::null_mut();

        cvt(unsafe { seccomp_notify_alloc(&mut notification, std::ptr::null_mut()) })?;

        Ok(Self(notification))
    }

    /// Receives a seccomp notification.
    ///
    /// This method receives a seccomp notification from the kernel and returns the notification
    /// as a `seccomp_notif` structure.
    ///
    /// # Blocking
    ///
    /// This method **will** block unless you've previously received a readable event from
    /// epoll / select / poll.
    pub fn recv(self, fd: RawFd) -> Result<seccomp_notif, io::Error> {
        cvt(unsafe { seccomp_notify_receive(fd, self.0) })?;
        Ok(unsafe { *self.0 })
    }
}

impl Notification {
    /// Constructs a `Notification` from a raw `seccomp_notif` structure and a file descriptor.
    ///
    /// This method takes a `seccomp_notif` structure and a file descriptor (`RawFd`) as input.
    /// It constructs a `Notification` instance by extracting the relevant fields from the `seccomp_notif`
    /// structure and the file descriptor.
    ///
    /// # Arguments
    ///
    /// * `notif` - A raw `seccomp_notif` structure containing the notification data.
    /// * `fd` - A file descriptor associated with the notification.
    ///
    /// # Returns
    ///
    /// A `Notification` instance with the extracted data.
    pub fn from_raw(notif: seccomp_notif, fd: RawFd) -> Self {
        Self {
            id: notif.id,
            pid: notif.pid,
            syscall: Sysno::from(notif.data.nr),
            args: notif.data.args,
            fd: fd.as_raw_fd(),
        }
    }

    /// Checks if the notification is valid.
    ///
    /// This method checks the validity of the notification by calling `seccomp_notify_id_valid`
    /// with the file descriptor and the notification ID. It returns `true` if the notification
    /// is valid, and `false` otherwise.
    ///
    /// # Returns
    ///
    /// `true` if the notification is valid, `false` otherwise.
    pub fn valid(&self) -> bool {
        cvt(unsafe { seccomp_notify_id_valid(self.fd, self.id) }).is_ok()
    }

    /// Opens the memory file of the process associated with the notification.
    ///
    /// This method attempts to open the memory file of the process identified by the notification's
    /// process ID. It constructs the path to the memory file and attempts to open it with read and
    /// write permissions. If the notification is not valid (i.e., the process has quit), it returns
    /// an error indicating that the process has quit.
    ///
    /// # Safety
    ///
    /// This method is unsafe because opening or reading the memory of a remote process is inherently prone to race conditions.
    /// While writing to remote memory is possible, it is **never** safe.
    /// Proceed with caution - here be demons!
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the memory file cannot be opened or if the notification is not valid.
    pub unsafe fn open(&self) -> Result<File, io::Error> {
        // Build the path to procfs
        // TODO: This is not very robust or tested against weird environments
        let path = format!("/proc/{}/mem", self.pid);
        let file = OpenOptions::new().read(true).write(true).open(path)?;

        // If our target got killed and the pid re-used we might be non the wiser so
        // we explicitly re-check here to make sure we actually have the correct file open.
        if !self.valid() {
            return Err(io::Error::new(
                ErrorKind::NotFound,
                "Process has quit while trying to access its memory!",
            ));
        }

        Ok(file)
    }
}

/// A wrapper around a file descriptor for seccomp notifications.
///
/// This struct is a wrapper around a `RawFd` that represents a file descriptor for seccomp notifications.
/// It implements the `AsRawFd` trait to allow access to the underlying file descriptor.
#[derive(Debug)]
struct SeccompFd(RawFd);

impl AsRawFd for SeccompFd {
    /// Returns the raw file descriptor.
    ///
    /// This method returns the underlying `RawFd` of the `SeccompFd`.
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// A stream of seccomp notifications.
///
/// This struct provides an asynchronous stream of seccomp notifications.
/// It wraps an `AsyncFd` around a `SeccompFd` to enable asynchronous operations on the seccomp file descriptor.
#[derive(Debug)]
pub struct NotificationStream {
    inner: AsyncFd<SeccompFd>,
}

impl NotificationStream {
    /// Creates a new `NotificationStream` from a raw file descriptor.
    ///
    /// This method initializes a `NotificationStream` with the given raw file descriptor.
    /// It sets up the `AsyncFd` to be ready for reading seccomp notifications.
    ///
    /// # Arguments
    ///
    /// * `fd` - The raw file descriptor for seccomp notifications.
    ///
    /// # Returns
    ///
    /// A `Result` containing a new `NotificationStream` or an `io::Error` if the operation fails.
    pub fn new(fd: RawFd) -> Result<Self, io::Error> {
        Ok(Self {
            inner: AsyncFd::with_interest(SeccompFd(fd), Interest::READABLE | Interest::WRITABLE)?,
        })
    }

    /// Receives a seccomp notification.
    ///
    /// This method will block until it receives a seccomp notification.
    /// You can prevent it from blocking by listening for `self.inner` to become readable
    /// using epoll / poll / select.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `Notification` or an `io::Error`.
    pub fn blocking_recv(&self) -> Result<Notification, io::Error> {
        let raw = RawNotification::new()?.recv(self.inner.as_raw_fd())?;
        Ok(Notification::from_raw(raw, self.inner.as_raw_fd()))
    }

    /// Receives a seccomp notification asynchronously.
    ///
    /// This method will not block unless other threads are simultaneously listening for notifications.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `Notification` or an `io::Error`.
    pub async fn recv(&self) -> Result<Notification, io::Error> {
        // TODO: This is kinda dangerous when other threads are waiting for a notification.
        let guard = self.inner.readable().await?;
        let result = self.blocking_recv();
        drop(guard);
        result
    }

    /// Sends a response to a seccomp notification.
    ///
    /// This method sends a response to a seccomp notification based on the provided `ResponseType`.
    ///
    /// # Arguments
    ///
    /// * `notif` - The notification to which the response is being sent.
    /// * `response_type` - The type of response to send.
    ///
    /// # Returns
    ///
    /// A `Result` indicating the success or failure of the operation.
    pub fn send(&self, notif: Notification, response_type: ResponseType) -> Result<(), io::Error> {
        let raw = RawResponse::new()?;
        raw.send(self.inner.as_raw_fd(), notif.id, response_type)?;
        Ok(())
    }

    /// Sends a continue response to a seccomp notification.
    ///
    /// This method sends a continue response to a seccomp notification.
    /// It returns a `Result` indicating the success or failure of the operation.
    ///
    /// # Arguments
    ///
    /// * `notif` - The notification to which the continue response is being sent.
    ///
    /// # Returns
    ///
    /// A `Result` indicating the success or failure of the operation.
    ///
    /// # Safety
    ///
    /// This method is unsafe because continuing a syscall is inherently prone to race conditions.
    /// See `RawResponse::send_continue` for more information.
    pub unsafe fn send_continue(&self, notif: Notification) -> Result<(), io::Error> {
        let raw = RawResponse::new()?;
        raw.send_continue(self.inner.as_raw_fd(), notif.id)?;
        Ok(())
    }
}

impl Stream for NotificationStream {
    type Item = Notification;

    /// Polls the stream for the next notification.
    ///
    /// This method polls the stream to check if a new notification is ready to be received.
    /// It returns a `Poll` indicating whether a notification is ready, an error occurred, or the operation is pending.
    ///
    /// # Arguments
    ///
    /// * `self` - A mutable reference to `self`.
    /// * `cx` - A context for the current task.
    ///
    /// # Returns
    ///
    /// A `Poll` indicating the state of the next notification.
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {


        match self.inner.poll_read_ready(cx) {
            Poll::Ready(Ok(mut guard)) => {
                if guard.ready().is_read_closed() {
                    Poll::Ready(None)
                } else{
                    let x = self.blocking_recv().ok();
                    guard.clear_ready();
                    Poll::Ready(x)
                }
            },
            Poll::Ready(Err(_)) => {
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending
        }

    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libseccomp::{
        reset_global_state, ScmpAction, ScmpArch, ScmpFd, ScmpFilterContext, ScmpSyscall,
    };
    use std::error::Error;
    use std::ffi::CStr;
    use std::fmt::Debug;
    use std::io::{Seek, SeekFrom, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex};
    use std::thread;

    use std::time::Duration;


    use std::thread::JoinHandle;

    use tokio::sync::oneshot;
    use tokio_stream::StreamExt;

    // libseccomp is **NOT** thread-safe, so we'll have to prevent our tests from running simultaneously.
    static SECCOMP_MUTEX: Mutex<()> = Mutex::new(());

    /// Runs a closure in a new thread with a seccomp() filter applied.
    /// Currently it will only filter `uname`.
    ///
    /// # Arguments
    ///
    /// * `fd_tx` - A oneshot sender to transmit the notification fd back to the main thread
    /// * `func` - The closure that will run in a seccomp'd thread
    fn run_with_seccomp<F, Output>(fd_tx: oneshot::Sender<ScmpFd>, func: F) -> JoinHandle<Output>
    where
        F: FnOnce() -> Output + Send + 'static,
        Output: Send + Clone + Debug + 'static
    {
        let handle = thread::spawn(move || {
            // Lock so we don't trash the global state of libseccomp with concurrent accesses
            let guard = SECCOMP_MUTEX.lock().unwrap();
            // Just to be sure, clean the global state.
            // This doesn't actually call into kernel, just clears a global struct.
            reset_global_state().unwrap();
            // Construct and load a filter
            let filter = setup().expect("Failed to setup SECCOMP!");
            // Retrieve the fd from libseccomp
            let fd = filter
                .get_notify_fd()
                .expect("Did not receive fd from seccomp()!");

            // Send the fd over to the main thread
            // This works because all threads within a process share fds
            fd_tx.send(fd).unwrap();

            // Evaluate the user supplied function
            let result = func();

            drop(filter);


            // We're done with libseccomp, so we can release the mutex
            drop(guard);

            result
        });

        handle
    }

    /// Creates and loads a seccomp() filter that will cause calls to `uname`
    /// to send notifications to user space.
    fn setup() -> Result<ScmpFilterContext, Box<dyn Error>> {
        // Creates a new filter that will allow everything by default
        let mut filter = ScmpFilterContext::new_filter(ScmpAction::Allow)?;
        // This will make the filter trigger for the native arch
        filter.add_arch(ScmpArch::Native)?;
        // Make the filter notify us for `uname`
        let syscall = ScmpSyscall::from_name("uname")?;
        filter.add_rule(ScmpAction::Notify, syscall)?;
        // Apply the filter to the current thread
        filter.load()?;

        Ok(filter)
    }

    #[tokio::test]
    async fn test_continue() -> Result<(), io::Error> {
        let (fd_tx, fd_rx) = oneshot::channel::<ScmpFd>();

        let handle = run_with_seccomp(fd_tx, move || {
            let mut n = unsafe { std::mem::zeroed() };
            let r = unsafe { libc::uname(&mut n) };
            assert_eq!(r, 0);
            unsafe { CStr::from_ptr(&n.sysname[0]) }
                .to_str()
                .expect("Invalid UTF-8 reply!")
                .to_owned()
        });

        let fd = fd_rx.await.expect("Did not receive FD!");

        let mut stream =
            NotificationStream::new(fd).expect("Failed to construct NotificationStream");

        let notification = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("Did not receive a notification in time!")
            .unwrap();

        assert!(matches!(notification.syscall, Sysno::uname));

        unsafe { stream.send_continue(notification) }.expect("Failed to send response");

        let sysname = handle.join().expect("Failed to wait for thread!");
        assert_eq!(sysname, "Linux");

        Ok(())
    }

    #[tokio::test]
    async fn test_intercept() -> Result<(), io::Error> {
        let (fd_tx, fd_rx) = oneshot::channel::<ScmpFd>();

        let handle = run_with_seccomp(fd_tx, move || {
            let mut n = unsafe { std::mem::zeroed() };
            let r = unsafe { libc::uname(&mut n) };
            assert_eq!(r, 0);
            unsafe { CStr::from_ptr(&n.sysname[0]) }
                .to_str()
                .expect("Invalid UTF-8 reply!")
                .to_owned()
        });

        let fd = fd_rx.await.expect("Did not receive FD!");

        let mut stream =
            NotificationStream::new(fd).expect("Failed to construct NotificationStream");

        let notification = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("Did not receive a notification in time!")
            .unwrap();

        assert!(matches!(notification.syscall, Sysno::uname));

        let mut file = unsafe { notification.open() }.expect("Failed to open memory!");
        file.seek(SeekFrom::Start(notification.args[0]))
            .expect("Failed to seek!");
        file.write_all(b"seccomp")
            .expect("Failed to write spoofed reply!");

        stream
            .send(notification, ResponseType::Success(0))
            .expect("Failed to send response");

        let sysname = handle.join().expect("Failed to wait for thread!");
        assert_eq!(sysname, "seccomp");

        Ok(())
    }


    #[tokio::test]
    async fn test_parallel() -> Result<(), io::Error> {
        let (fd_tx, fd_rx) = oneshot::channel::<ScmpFd>();

        let handle = run_with_seccomp(fd_tx, move || {

            let first = std::thread::spawn(move || {
                for _ in 0..20 {
                    let mut n = unsafe { std::mem::zeroed() };
                    let r = unsafe { libc::uname(&mut n) };
                    assert_eq!(r, 0);
                }
            });

            let second = std::thread::spawn(move || {
                for _ in 0..20 {
                    let mut n = unsafe { std::mem::zeroed() };
                    let r = unsafe { libc::uname(&mut n) };
                    assert_eq!(r, 0);
                }
            });

            first.join().unwrap();
            second.join().unwrap();
        });

        let fd = fd_rx.await.expect("Did not receive FD!");

        let mut stream =
            NotificationStream::new(fd).expect("Failed to construct NotificationStream");
        
        let counter = AtomicUsize::new(0);
        
        while let Some(notification) = stream.next().await {
            counter.fetch_add(1, Ordering::Relaxed);
            unsafe { stream.send_continue(notification) }.unwrap();
        }

        assert_eq!(counter.into_inner(), 40);
        handle.join().unwrap();
        unsafe {
            cvt(libc::close(fd)).unwrap();
        }

        Ok(())
    }
}

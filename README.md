# seccomp-stream

[seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html) was amended by [seccomp_unotify](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html) in Kernel version 5.0 adding the ability to add a user space notifier for seccomp events.

Support for this was added to [libseccomp-rs](https://github.com/libseccomp-rs/libseccomp-rs) already but their implementation is, while complete, blocking and as such doesn't lend itself to modern, async Rust.

## Usage

After receiving a notification you may choose to let the system call pass and continue along. 
This however is _unsafe_ because the arguments might've been altered in the target process by a signal.

For more information see the man page for [seccomp_unotify](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html).

```rust
let mut stream = NotificationStream::new(fd).expect("Failed to construct NotificationStream");

while let Some(notification) = stream.next().await {
    unsafe { stream.send_continue(notification) }.unwrap();
}
```

You may alternatively choose to run the system call in place of the target process after checking the parameters for validity.

While you can open the memory for reading and writing using `Notification::open` but you're exposing yourself to race conditions.

Writing to the targets memory is **never** safe as outlined by the man page.

```rust
let mut stream = NotificationStream::new(fd).expect("Failed to construct NotificationStream");

while let Some(notification) = stream.next().await {
    // Interact with the process in some way here
    stream
        .send(notification, ResponseType::Success(0))
        .expect("Failed to send response");
}
```

A third option would be to inject an error and prevent the system call from proceeding any further.
This will force the target process from using its own error handling.

```rust
let mut stream = NotificationStream::new(fd).expect("Failed to construct NotificationStream");

while let Some(notification) = stream.next().await {
    stream
        .send(notification, ResponseType::RawError(libc::EPERM))
        .expect("Failed to send response");
}
```

## Safety

After installing the filter, seccomp will return a file descriptor that can be interacted with using [epoll](https://man7.org/linux/man-pages/man7/epoll.7.html).

Once epoll signals that the file descriptor is readable, a call to the ioctl will not block. 
In any other cases the call **will** block. 
You may choose to use this library that way but be careful of mixing blocking and non-blocking methods as that might mess up the blocking guarantees.

Some other things previously outlined that you **shouldn't** do.

- Carelessly read another processes memory
- Assume your target process is fully stopped
- Write another processes memory

If you trust your target you may choose to still do these things regardless and things (probably) won't catch fire.

## Compatibility

This library requires the following things to be present:

- A Linux kernel version 5.0 or higher
- libseccomp and libseccomp-dev version 2.5 or higher
- A somewhat recent version of Rust
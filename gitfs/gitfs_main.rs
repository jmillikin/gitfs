// Copyright (c) 2024 John Millikin <john@john-millikin.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;
use std::mem::{size_of, zeroed};
use std::os::fd::{
	AsRawFd,
	FromRawFd,
	IntoRawFd,
	OwnedFd,
	RawFd,
};
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::ptr;

mod gitfs;

fn mount_fusermount(target: &OsStr) -> fuse_libc::FuseServerSocket {
	let (pipe0, pipe1) = UnixStream::pair().unwrap();
	let pipe0_fd = pipe0.as_raw_fd();
	unsafe {
        let flags = libc::fcntl(pipe0_fd, libc::F_GETFD);
        libc::fcntl(pipe0_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
	}

    let mut child = spawn_fusermount("/usr/bin/fusermount3", pipe0_fd, target);
	if child.is_err() {
		let child2 = spawn_fusermount("fusermount3", pipe0_fd, target);
		if child2.is_ok() {
			child = child2;
		}
	}
	let mut fusermount = child.unwrap();

	std::mem::drop(pipe0);
	let received_fd = unsafe { receive_fd(pipe1) }.unwrap();
	fusermount.wait().unwrap();

	let received_fd = received_fd.into_raw_fd();
	unsafe { fuse_libc::FuseServerSocket::from_raw_fd(received_fd) }
}

fn spawn_fusermount(
	fusermount: impl AsRef<OsStr>,
	comm_fd: RawFd,
	target: &OsStr,
) -> std::io::Result<std::process::Child> {
	Command::new(fusermount.as_ref())
		.env("_FUSE_COMMFD", &comm_fd.to_string())
		.arg("-o")
		.arg("fsname=gitfs,subtype=gitfs")
		.arg("--")
		.arg(target)
        .spawn()
}

fn libc_errno() -> libc::c_int {
	unsafe {
		#[cfg(target_os = "linux")]
		return *libc::__errno_location();

		#[cfg(target_os = "freebsd")]
		return *libc::__error();
	}
}

unsafe fn receive_fd(
	pipe: std::os::unix::net::UnixStream,
) -> std::io::Result<std::os::fd::OwnedFd> {
	let pipe_fd = pipe.as_raw_fd();

	let mut buf = [0u8; 1];
	let mut iov: libc::iovec = zeroed();
	iov.iov_base = ptr::from_mut(&mut buf).cast();
	iov.iov_len = 1;

    let mut msg: libc::msghdr = zeroed();
	msg.msg_iov = ptr::from_mut(&mut iov);
	msg.msg_iovlen = 1;

	const CCMSG_LEN: usize = unsafe { libc::CMSG_SPACE(4) } as _;
	let mut ccmsg = [0u8; CCMSG_LEN];
	msg.msg_control = ptr::from_mut(&mut ccmsg).cast();
	msg.msg_controllen = CCMSG_LEN as _;

	let msg_ptr = ptr::from_mut(&mut msg);
	loop {
		let rc = libc::recvmsg(pipe_fd, msg_ptr, 0);
		if rc == -1 {
			let errno = libc_errno();
			if errno == libc::EINTR {
				continue;
			}
			return Err(std::io::Error::from_raw_os_error(errno));
		}
		if rc == 0 {
			return Err(std::io::ErrorKind::UnexpectedEof.into());
		}
		break;
	}

	let cmsg_ptr = libc::CMSG_FIRSTHDR(&msg);
	if cmsg_ptr.is_null() {
		return Err(std::io::ErrorKind::Other.into());
	}

	let mut cmsg: libc::cmsghdr = zeroed();
	ptr::copy_nonoverlapping(
		cmsg_ptr.cast::<u8>(),
		ptr::from_mut(&mut cmsg).cast::<u8>(),
		size_of::<libc::cmsghdr>(),
	);
	if cmsg.cmsg_type != libc::SCM_RIGHTS {
		return Err(std::io::ErrorKind::Other.into());
	}
	let cmsg_data = libc::CMSG_DATA(cmsg_ptr);

	let received_fd = cmsg_data.cast::<[u8; 4]>().read();
	Ok(OwnedFd::from_raw_fd(i32::from_ne_bytes(received_fd)))
}

fn main() {
	let repo_path = std::env::args_os().nth(1).unwrap();
	let mount_target = std::env::args_os().nth(2).unwrap();

	let repo = git2::Repository::open(repo_path).unwrap();
	let dev_fuse = mount_fusermount(&mount_target);
	let conn = fuse::server::FuseServer::new().connect(dev_fuse).unwrap();

	let gitfs = gitfs::GitFs::new(&conn, repo);
	fuse_std::serve_fuse(&conn, &gitfs);
}

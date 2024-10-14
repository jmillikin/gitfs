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

use std::cmp;
use std::collections::HashMap;
use std::ffi::CString;
use std::mem::drop;
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fuse::{
	NodeId,
	NodeName,
};
use fuse::os::OsError;
use fuse::server;
use fuse::server::FuseRequest;

fn getuid() -> u32 {
	unsafe { libc::getuid() }
}

fn getgid() -> u32 {
	unsafe { libc::getgid() }
}

// GitFs {{{

pub(crate) struct GitFs<'a, S> {
	conn: &'a fuse::server::FuseConnection<S>,
	vfs: fuse_vfs::Filesystem<'a, S>,
}

impl<'a, S> GitFs<'a, S> {
	pub(crate) fn new(
		conn: &'a fuse::server::FuseConnection<S>,
		repo: git2::Repository,
	) -> GitFs<'a, S> {
		let root = Arc::new(GitRoot::new(repo));
		Self {
			conn,
			vfs: fuse_vfs::Filesystem::new(conn, root),
		}
	}
}

impl<S: server::FuseSocket> server::FuseHandlers for GitFs<'_, S>
where
	S::Error: std::fmt::Debug,
{
	fn unimplemented(&self, request: FuseRequest<'_>) {
		use fuse::server::SendError;
		match self.conn.reply(request.id()).err(OsError::UNIMPLEMENTED) {
			Ok(_) => {},
			Err(SendError::NotFound(_)) => {},
			err => err.unwrap(),
		}
	}

	fn dispatch(&self, request: FuseRequest<'_>) {
		use fuse::server::{ServerError, SendError};
		let Some(result) = self.vfs.dispatch(request) else {
			self.unimplemented(request);
			return;
		};
		let Err(err) = result else {
			return;
		};
		match err {
			ServerError::SendError(SendError::NotFound(_)) => {},
			_ => Err(err).unwrap(),
		}
	}
}

// GitFs }}}

// GitNodeIdMap {{{

struct GitNodeIdMap {
	next_id: u64,
	node_ids: HashMap<NodeKey, NodeId>,
}

#[derive(Copy, Clone, Eq, Hash, PartialEq)]
enum NodeKey {
	OID(git2::Oid),
	BranchHash(u64),
	SpecialByBranch,
	SpecialByCommit,
	SpecialByTag,
}

impl NodeKey {
	fn branch(name: &[u8]) -> NodeKey {
		use std::hash::Hasher;
		let mut hasher = std::hash::DefaultHasher::new();
		hasher.write(name);
		NodeKey::BranchHash(hasher.finish())
	}
}

impl<'a> GitNodeIdMap {
	fn ensure(&mut self, key: NodeKey) -> NodeId {
		if let Some(node_id) = self.node_ids.get(&key) {
			return *node_id;
		}
		let node_id = NodeId::new(self.next_id).unwrap();
		self.next_id += 1;
		self.node_ids.insert(key, node_id);
		node_id
	}
}

// GitNodeIdMap }}}

// GitRoot {{{

struct GitRoot {
	by_branch: Arc<GitByBranch>,
	by_branch_id: NodeId,
	by_tag: Arc<GitByTag>,
	by_tag_id: NodeId,
	by_commit: Arc<GitByCommit>,
	by_commit_id: NodeId,
}

impl GitRoot {
	fn new(repo: git2::Repository) -> GitRoot {
		let mut node_id_map = GitNodeIdMap {
			next_id: 2,
			node_ids: HashMap::new(),
		};

		let by_branch_id = node_id_map.ensure(NodeKey::SpecialByBranch);
		let by_tag_id = node_id_map.ensure(NodeKey::SpecialByTag);
		let by_commit_id = node_id_map.ensure(NodeKey::SpecialByCommit);

		let repo = Arc::new(Mutex::new(repo));
		let node_id_map = Arc::new(Mutex::new(node_id_map));

		let by_branch = Arc::new(GitByBranch {
			repo: repo.clone(),
			node_id: by_branch_id,
			node_id_map: node_id_map.clone(),
		});
		let by_tag = Arc::new(GitByTag {
			repo: repo.clone(),
			node_id: by_tag_id,
			node_id_map: node_id_map.clone(),
		});
		let by_commit = Arc::new(GitByCommit {
			repo: repo.clone(),
			node_id: by_commit_id,
			node_id_map: node_id_map.clone(),
		});
		Self {
			by_branch,
			by_branch_id,
			by_tag,
			by_tag_id,
			by_commit,
			by_commit_id,
		}
	}
}

impl fuse_vfs::Node for GitRoot {
	fn as_directory(&self) -> Option<&dyn fuse_vfs::Directory> {
		Some(self)
	}

	fn getattr(
		&self,
		_header: &fuse::RequestHeader,
		_request: server::GetattrRequest<'_>,
	) -> Result<fuse_vfs::GetattrResult, fuse::Error> {
		let mut attr = fuse::NodeAttr::new(fuse::NodeId::ROOT);
		attr.set_user_id(getuid());
		attr.set_group_id(getgid());
		attr.set_mode(fuse::FileMode::S_IFDIR | 0o755);
		attr.set_size(4096);
		attr.set_link_count(4);
		let mut result = fuse_vfs::GetattrResult::new(attr);
		result.cache_timeout = Duration::MAX;
		Ok(result)
	}
}

impl fuse_vfs::Directory for GitRoot {
	fn lookup(
		&self,
		_header: &fuse::RequestHeader,
		request: server::LookupRequest<'_>,
	) -> Result<fuse_vfs::LookupResult, fuse::Error> {
		use fuse_vfs::LookupResult;

		let name = request.name();
		let mut result;
		if name == "by-branch" {
			let mut attr = fuse::NodeAttr::new(self.by_branch_id);
			attr.set_user_id(getuid());
			attr.set_group_id(getgid());
			attr.set_link_count(2);
			attr.set_mode(fuse::FileMode::S_IFDIR | 0o755);
			attr.set_size(4096);
			result = LookupResult::found(self.by_branch.clone(), attr);
		} else if name == "by-tag" {
			let mut attr = fuse::NodeAttr::new(self.by_tag_id);
			attr.set_user_id(getuid());
			attr.set_group_id(getgid());
			attr.set_link_count(2);
			attr.set_mode(fuse::FileMode::S_IFDIR | 0o755);
			attr.set_size(4096);
			result = LookupResult::found(self.by_tag.clone(), attr);
		} else if name == "by-commit" {
			let mut attr = fuse::NodeAttr::new(self.by_commit_id);
			attr.set_user_id(getuid());
			attr.set_group_id(getgid());
			attr.set_link_count(2);
			attr.set_mode(fuse::FileMode::S_IFDIR | 0o755);
			attr.set_size(4096);
			result = LookupResult::found(self.by_commit.clone(), attr);
		} else {
			result = LookupResult::not_found();
		}

		result.entry_cache_timeout = Duration::MAX;
		result.attr_cache_timeout = Duration::MAX;
		Ok(result)
	}

	fn opendir(
		&self,
		_header: &fuse::RequestHeader,
		_request: server::OpendirRequest<'_>,
	) -> Result<fuse_vfs::OpendirResult, fuse::Error> {
		use fuse_vfs::StaticDirectoryEntry as Entry;
		let mut entries = Vec::new();
		{
			let name = NodeName::new("by-branch").unwrap();
			let mut entry = Entry::new(name, self.by_branch_id);
			entry.node_attr.set_mode(fuse::FileMode::S_IFDIR | 0o755);
			entries.push(entry);
		}
		{
			let name = NodeName::new("by-tag").unwrap();
			let mut entry = Entry::new(name, self.by_tag_id);
			entry.node_attr.set_mode(fuse::FileMode::S_IFDIR | 0o755);
			entries.push(entry);
		}
		{
			let name = NodeName::new("by-commit").unwrap();
			let mut entry = Entry::new(name, self.by_commit_id);
			entry.node_attr.set_mode(fuse::FileMode::S_IFDIR | 0o755);
			entries.push(entry);
		}
		let handle = Arc::new(fuse_vfs::StaticDirectoryHandle::new(entries));
		Ok(fuse_vfs::OpendirResult::new(handle))
	}
}

// GitRoot }}}

// GitByTag {{{

struct GitByTag {
	repo: Arc<Mutex<git2::Repository>>,
	node_id: NodeId,
	node_id_map: Arc<Mutex<GitNodeIdMap>>,
}

impl fuse_vfs::Node for GitByTag {
	fn as_directory(&self) -> Option<&dyn fuse_vfs::Directory> {
		Some(self)
	}

	fn getattr(
		&self,
		_header: &fuse::RequestHeader,
		_request: server::GetattrRequest<'_>,
	) -> Result<fuse_vfs::GetattrResult, fuse::Error> {
		let mut attr = fuse::NodeAttr::new(self.node_id);
		attr.set_user_id(getuid());
		attr.set_group_id(getgid());
		attr.set_mode(fuse::FileMode::S_IFDIR | 0o755);
		attr.set_size(4096);
		attr.set_link_count(2);
		let mut result = fuse_vfs::GetattrResult::new(attr);
		result.cache_timeout = Duration::MAX;
		Ok(result)
	}
}

impl fuse_vfs::Directory for GitByTag {
	fn lookup(
		&self,
		_header: &fuse::RequestHeader,
		request: server::LookupRequest<'_>,
	) -> Result<fuse_vfs::LookupResult, fuse::Error> {
		let node_name = request.name();
		let repo = self.repo.lock().unwrap();

		let mut tag_oid = None;
		let foreach_result = repo.tag_foreach(|oid, name| {
			let tag_name = name
				.split(|b| *b == b'/')
				.collect::<Vec<&[u8]>>()
				.pop()
				.unwrap();
			if node_name.as_bytes() == tag_name {
				tag_oid = Some(oid);
				return false;
			}
			true
		});
		if let Err(err) = foreach_result {
			todo!("{:?}", err);
		}
		let Some(tag_oid) = tag_oid else {
			return Err(OsError::NOT_FOUND);
		};

		let mut commit = None;
		if let Ok(tag) = repo.find_tag(tag_oid) {
			if let Ok(target) = tag.target() {
				if let Some(target) = target.as_commit() {
					let commit_time = fuse::UnixTime::from_seconds(
						target.time().seconds(),
					);
					commit = Some((target.id(), commit_time));
				}
			}
		}
		let Some((commit_oid, commit_time)) = commit else {
			return Err(OsError::NOT_FOUND);
		};

		let mut node_id_map = self.node_id_map.lock().unwrap();
		let node_id = node_id_map.ensure(NodeKey::OID(tag_oid));
		drop(node_id_map);

		let node = Arc::new(GitSymlinkToCommit {
			repo: self.repo.clone(),
			node_id,
			commit_oid,
		});
		let mut node_attr = fuse::NodeAttr::new(node_id);
		node_attr.set_user_id(getuid());
		node_attr.set_group_id(getgid());
		node_attr.set_mode(fuse::FileMode::S_IFLNK | 0o755);
		node_attr.set_size(COMMIT_SYMLINK_SIZE);
		node_attr.set_link_count(1);
		node_attr.set_ctime(commit_time);
		node_attr.set_mtime(commit_time);
		let mut result = fuse_vfs::LookupResult::found(node, node_attr);
		result.entry_cache_timeout = Duration::from_secs(1);
		result.attr_cache_timeout = Duration::from_secs(1);
		Ok(result)
	}

	fn opendir(
		&self,
		_header: &fuse::RequestHeader,
		_request: server::OpendirRequest<'_>,
	) -> Result<fuse_vfs::OpendirResult, fuse::Error> {
		let handle = Arc::new(GitByTagHandle {
			repo: self.repo.clone(),
			node_id_map: self.node_id_map.clone(),
		});
		Ok(fuse_vfs::OpendirResult::new(handle))
	}
}

// GitByTag }}}

// GitByTagHandle {{{

struct GitByTagHandle {
	repo: Arc<Mutex<git2::Repository>>,
	node_id_map: Arc<Mutex<GitNodeIdMap>>,
}

impl fuse_vfs::DirectoryHandle for GitByTagHandle {
	fn as_readdir_handle(&self) -> Option<&dyn fuse_vfs::ReaddirHandle> {
		Some(self)
	}
}

impl fuse_vfs::ReaddirHandle for GitByTagHandle {
	fn readdir(
		&self,
		_header: &fuse::RequestHeader,
		request: server::ReaddirRequest<'_>,
	) -> Result<fuse_vfs::ReaddirResult, fuse::Error> {
		let size = cmp::min(request.size() as u32, i32::MAX as u32);
		let start_offset = request.offset().map_or(0, |o| o.get());

		let mut buf = vec![0u8; size as usize];
		let mut writer = server::ReaddirEntriesWriter::new(&mut buf);

		let repo = self.repo.lock().unwrap();
		let mut node_id_map = self.node_id_map.lock().unwrap();

		let mut next_node_offset: u64 = 1;
		let foreach_result = repo.tag_foreach(|oid, name| {
			let node_offset = NonZeroU64::new(next_node_offset).unwrap();
			next_node_offset += 1;

			if node_offset.get() <= start_offset {
				return true;
			}

			let mut ok = false;
			if let Ok(tag) = repo.find_tag(oid) {
				if let Ok(target) = tag.target() {
					if target.as_commit().is_some() {
						ok = true;
					}
				}
			}
			if !ok {
				return true;
			}

			let tag_name = name
				.split(|b| *b == b'/')
				.collect::<Vec<&[u8]>>()
				.pop()
				.unwrap();
			let Ok(name) = NodeName::from_bytes(tag_name) else {
				return true;
			};
			let id = node_id_map.ensure(NodeKey::OID(oid));
			let mut entry = server::ReaddirEntry::new(id, name, node_offset);
			entry.set_file_type(fuse::FileType::Symlink);
			if let Err(_) = writer.try_push(&entry) {
				return false;
			}
			true
		});
		if let Err(err) = foreach_result {
			todo!("{:?}", err);
		}

		let buf_len = writer.position();
		buf.truncate(buf_len);
		Ok(fuse_vfs::ReaddirResult::new(buf))
	}
}

// GitByTagHandle }}}

// GitSymlinkToCommit {{{

struct GitSymlinkToCommit {
	repo: Arc<Mutex<git2::Repository>>,
	node_id: NodeId,
	commit_oid: git2::Oid,
}

const SHA1_HEX_LEN: u64 = 40;
const COMMIT_SYMLINK_SIZE: u64 = ("../by-commit/".len() as u64) + SHA1_HEX_LEN;

impl fuse_vfs::Node for GitSymlinkToCommit {
	fn as_symlink(&self) -> Option<&dyn fuse_vfs::Symlink> {
		Some(self)
	}

	fn getattr(
		&self,
		_header: &fuse::RequestHeader,
		_request: server::GetattrRequest<'_>,
	) -> Result<fuse_vfs::GetattrResult, fuse::Error> {
		let repo = self.repo.lock().unwrap();
		let Ok(commit) = repo.find_commit(self.commit_oid) else {
			return Err(OsError::NOT_FOUND);
		};
		let commit_time = fuse::UnixTime::from_seconds(commit.time().seconds());
		drop(commit);
		drop(repo);

		let mut attr = fuse::NodeAttr::new(self.node_id);
		attr.set_user_id(getuid());
		attr.set_group_id(getgid());
		attr.set_mode(fuse::FileMode::S_IFLNK | 0o755);
		attr.set_size(COMMIT_SYMLINK_SIZE);
		attr.set_link_count(1);
		attr.set_ctime(commit_time);
		attr.set_mtime(commit_time);
		let mut result = fuse_vfs::GetattrResult::new(attr);
		result.cache_timeout = Duration::from_secs(1);
		Ok(result)
	}
}

impl fuse_vfs::Symlink for GitSymlinkToCommit {
	fn readlink(
		&self,
		_header: &fuse::RequestHeader,
		_request: server::ReadlinkRequest<'_>,
	) -> Result<fuse_vfs::ReadlinkResult, fuse::Error> {
		let target = format!("../by-commit/{}\x00", self.commit_oid);
		let target_cstr = unsafe {
			CString::from_vec_with_nul_unchecked(target.into_bytes())
		};
		return Ok(fuse_vfs::ReadlinkResult::new(target_cstr));
	}
}

// GitSymlinkToCommit }}}

// GitByBranch {{{

struct GitByBranch {
	repo: Arc<Mutex<git2::Repository>>,
	node_id: NodeId,
	node_id_map: Arc<Mutex<GitNodeIdMap>>,
}

impl fuse_vfs::Node for GitByBranch {
	fn as_directory(&self) -> Option<&dyn fuse_vfs::Directory> {
		Some(self)
	}

	fn getattr(
		&self,
		_header: &fuse::RequestHeader,
		_request: server::GetattrRequest<'_>,
	) -> Result<fuse_vfs::GetattrResult, fuse::Error> {
		let mut attr = fuse::NodeAttr::new(self.node_id);
		attr.set_user_id(getuid());
		attr.set_group_id(getgid());
		attr.set_mode(fuse::FileMode::S_IFDIR | 0o755);
		attr.set_size(4096);
		attr.set_link_count(2);
		let mut result = fuse_vfs::GetattrResult::new(attr);
		result.cache_timeout = Duration::MAX;
		Ok(result)
	}
}

impl fuse_vfs::Directory for GitByBranch {
	fn lookup(
		&self,
		_header: &fuse::RequestHeader,
		request: server::LookupRequest<'_>,
	) -> Result<fuse_vfs::LookupResult, fuse::Error> {
		let Ok(name) = request.name().as_str() else {
			return Err(OsError::NOT_FOUND);
		};
		let repo = self.repo.lock().unwrap();
		let Ok(branch) = repo.find_branch(name, git2::BranchType::Local) else {
			return Err(OsError::NOT_FOUND);
		};
		let Ok(commit) = branch.get().peel_to_commit() else {
			return Err(OsError::NOT_FOUND);
		};
		let commit_oid = commit.id();
		let commit_time = fuse::UnixTime::from_seconds(commit.time().seconds());
		drop(commit);
		drop(branch);
		drop(repo);

		let mut node_id_map = self.node_id_map.lock().unwrap();
		let node_id = node_id_map.ensure(NodeKey::branch(name.as_bytes()));
		drop(node_id_map);

		let node = Arc::new(GitSymlinkToCommit {
			repo: self.repo.clone(),
			node_id,
			commit_oid,
		});
		let mut node_attr = fuse::NodeAttr::new(node_id);
		node_attr.set_user_id(getuid());
		node_attr.set_group_id(getgid());
		node_attr.set_mode(fuse::FileMode::S_IFLNK | 0o755);
		node_attr.set_size(COMMIT_SYMLINK_SIZE);
		node_attr.set_link_count(1);
		node_attr.set_ctime(commit_time);
		node_attr.set_mtime(commit_time);
		let mut result = fuse_vfs::LookupResult::found(node, node_attr);
		result.entry_cache_timeout = Duration::from_secs(1);
		result.attr_cache_timeout = Duration::from_secs(1);
		Ok(result)
	}

	fn opendir(
		&self,
		_header: &fuse::RequestHeader,
		_request: server::OpendirRequest<'_>,
	) -> Result<fuse_vfs::OpendirResult, fuse::Error> {
		let handle = Arc::new(GitByBranchHandle {
			repo: self.repo.clone(),
			node_id_map: self.node_id_map.clone(),
		});
		Ok(fuse_vfs::OpendirResult::new(handle))
	}
}

// GitByBranch }}}

// GitByBranchHandle {{{

struct GitByBranchHandle {
	repo: Arc<Mutex<git2::Repository>>,
	node_id_map: Arc<Mutex<GitNodeIdMap>>,
}

impl fuse_vfs::DirectoryHandle for GitByBranchHandle {
	fn as_readdir_handle(&self) -> Option<&dyn fuse_vfs::ReaddirHandle> {
		Some(self)
	}
}

impl fuse_vfs::ReaddirHandle for GitByBranchHandle {
	fn readdir(
		&self,
		_header: &fuse::RequestHeader,
		request: server::ReaddirRequest<'_>,
	) -> Result<fuse_vfs::ReaddirResult, fuse::Error> {
		let size = cmp::min(request.size() as u32, i32::MAX as u32);
		let start_offset = request.offset().map_or(0, |o| o.get());

		let mut buf = vec![0u8; size as usize];
		let mut writer = server::ReaddirEntriesWriter::new(&mut buf);

		let repo = self.repo.lock().unwrap();
		let mut node_id_map = self.node_id_map.lock().unwrap();

		let Ok(branches) = repo.branches(Some(git2::BranchType::Local)) else {
			return Err(OsError::UNAVAILABLE);
		};

		let mut next_node_offset: u64 = 1;
		for branch_result in branches {
			let Ok((branch, _)) = branch_result else {
				continue;
			};

			let node_offset = NonZeroU64::new(next_node_offset).unwrap();
			next_node_offset += 1;
			if node_offset.get() <= start_offset {
				continue;
			}
			let Ok(branch_name) = branch.name_bytes() else {
				continue;
			};
			let Ok(name) = NodeName::from_bytes(branch_name) else {
				continue;
			};

			let id = node_id_map.ensure(NodeKey::branch(branch_name));
			let mut entry = server::ReaddirEntry::new(id, name, node_offset);
			entry.set_file_type(fuse::FileType::Symlink);
			if let Err(_) = writer.try_push(&entry) {
				break;
			}
		}

		let buf_len = writer.position();
		buf.truncate(buf_len);
		Ok(fuse_vfs::ReaddirResult::new(buf))
	}
}

// GitByBranchHandle }}}

// GitByCommit {{{

struct GitByCommit {
	repo: Arc<Mutex<git2::Repository>>,
	node_id: NodeId,
	node_id_map: Arc<Mutex<GitNodeIdMap>>,
}

impl fuse_vfs::Node for GitByCommit {
	fn as_directory(&self) -> Option<&dyn fuse_vfs::Directory> {
		Some(self)
	}

	fn getattr(
		&self,
		_header: &fuse::RequestHeader,
		_request: server::GetattrRequest<'_>,
	) -> Result<fuse_vfs::GetattrResult, fuse::Error> {
		let mut attr = fuse::NodeAttr::new(self.node_id);
		attr.set_user_id(getuid());
		attr.set_group_id(getgid());
		attr.set_mode(fuse::FileMode::S_IFDIR | 0o755);
		attr.set_size(4096);
		attr.set_link_count(2);
		let mut result = fuse_vfs::GetattrResult::new(attr);
		result.cache_timeout = Duration::MAX;
		Ok(result)
	}
}

impl fuse_vfs::Directory for GitByCommit {
	fn lookup(
		&self,
		_header: &fuse::RequestHeader,
		request: server::LookupRequest<'_>,
	) -> Result<fuse_vfs::LookupResult, fuse::Error> {
		let name = request.name();
		let Ok(name_str) = name.as_str() else {
			return Err(OsError::NOT_FOUND);
		};
		let Ok(commit_oid) = git2::Oid::from_str(name_str) else {
			return Err(OsError::NOT_FOUND);
		};

		let repo = self.repo.lock().unwrap();
		let Ok(commit) = repo.find_commit(commit_oid) else {
			return Err(OsError::NOT_FOUND);
		};
		let commit_time = fuse::UnixTime::from_seconds(commit.time().seconds());
		let Ok(tree) = commit.tree() else {
			return Err(OsError::NOT_FOUND);
		};
		let tree_oid = tree.id();
		let tree_len = tree.len();
		drop(tree);
		drop(commit);
		drop(repo);

		let mut node_id_map = self.node_id_map.lock().unwrap();
		let node_id = node_id_map.ensure(NodeKey::OID(commit_oid));
		drop(node_id_map);

		let link_count = (tree_len as u32) + 2;
		let node = Arc::new(GitTreeDir {
			repo: self.repo.clone(),
			node_id_map: self.node_id_map.clone(),
			node_id,
			commit_oid,
			commit_time,
			tree_oid,
			link_count,
		});

		let mut node_attr = fuse::NodeAttr::new(node_id);
		node_attr.set_user_id(getuid());
		node_attr.set_group_id(getgid());
		node_attr.set_mode(fuse::FileMode::S_IFDIR | 0o755);
		node_attr.set_size(4096);
		node_attr.set_link_count(link_count);
		node_attr.set_ctime(commit_time);
		node_attr.set_mtime(commit_time);
		let mut result = fuse_vfs::LookupResult::found(node, node_attr);
		result.entry_cache_timeout = Duration::MAX;
		result.attr_cache_timeout = Duration::MAX;
		Ok(result)
	}

	fn opendir(
		&self,
		_header: &fuse::RequestHeader,
		_request: server::OpendirRequest<'_>,
	) -> Result<fuse_vfs::OpendirResult, fuse::Error> {
		let handle = Arc::new(fuse_vfs::StaticDirectoryHandle::new(Vec::new()));
		Ok(fuse_vfs::OpendirResult::new(handle))
	}
}

// GitByCommit }}}

// GitTreeDir {{{

struct GitTreeDir {
	repo: Arc<Mutex<git2::Repository>>,
	node_id_map: Arc<Mutex<GitNodeIdMap>>,
	node_id: NodeId,
	commit_oid: git2::Oid,
	commit_time: fuse::UnixTime,
	tree_oid: git2::Oid,
	link_count: u32,
}

impl fuse_vfs::Node for GitTreeDir {
	fn as_directory(&self) -> Option<&dyn fuse_vfs::Directory> {
		Some(self)
	}

	fn getattr(
		&self,
		_header: &fuse::RequestHeader,
		_request: server::GetattrRequest<'_>,
	) -> Result<fuse_vfs::GetattrResult, fuse::Error> {
		let mut attr = fuse::NodeAttr::new(self.node_id);
		attr.set_user_id(getuid());
		attr.set_group_id(getgid());
		attr.set_mode(fuse::FileMode::S_IFDIR | 0o755);
		attr.set_size(4096);
		attr.set_link_count(self.link_count);
		attr.set_ctime(self.commit_time);
		attr.set_mtime(self.commit_time);
		let mut result = fuse_vfs::GetattrResult::new(attr);
		result.cache_timeout = Duration::MAX;
		Ok(result)
	}
}

impl fuse_vfs::Directory for GitTreeDir {
	fn lookup(
		&self,
		_header: &fuse::RequestHeader,
		request: server::LookupRequest<'_>,
	) -> Result<fuse_vfs::LookupResult, fuse::Error> {
		let name = request.name();
		let repo = self.repo.lock().unwrap();
		let Ok(commit) = repo.find_commit(self.commit_oid) else {
			return Err(OsError::NOT_FOUND);
		};
		let Ok(tree) = repo.find_tree(self.tree_oid) else {
			return Err(OsError::NOT_FOUND);
		};
		let Some(entry) = tree.get_name_bytes(name.as_bytes()) else {
			return Err(OsError::NOT_FOUND);
		};

		enum EntryObject {
			Tree(git2::Oid, usize /* len */),
			Blob(git2::Oid, u64 /* size */),
		}

		let entry_object_id = match entry.kind() {
			Some(git2::ObjectType::Tree) => {
				let Ok(obj) = entry.to_object(&repo) else {
					return Err(OsError::NOT_FOUND);
				};
				let Some(tree) = obj.as_tree() else {
					return Err(OsError::NOT_FOUND);
				};
				EntryObject::Tree(tree.id(), tree.len())
			},
			Some(git2::ObjectType::Blob) => {
				let Ok(obj) = entry.to_object(&repo) else {
					return Err(OsError::NOT_FOUND);
				};
				let Some(blob) = obj.as_blob() else {
					return Err(OsError::NOT_FOUND);
				};
				EntryObject::Blob(blob.id(), blob.size() as u64)
			},
			_ => return Err(OsError::NOT_FOUND),
		};

		let entry_oid = entry.id();
		let entry_filemode = entry.filemode();
		drop(entry);
		drop(tree);
		drop(commit);
		drop(repo);

		let mut node_id_map = self.node_id_map.lock().unwrap();
		let node_id = node_id_map.ensure(NodeKey::OID(entry_oid));
		drop(node_id_map);

		let mut node_attr = fuse::NodeAttr::new(node_id);
		node_attr.set_user_id(getuid());
		node_attr.set_group_id(getgid());
		node_attr.set_ctime(self.commit_time);
		node_attr.set_mtime(self.commit_time);

		let mut result = match entry_object_id {
			EntryObject::Tree(tree_oid, tree_len) => {
				let link_count = (tree_len as u32) + 2;
				let node = Arc::new(GitTreeDir {
					repo: self.repo.clone(),
					node_id_map: self.node_id_map.clone(),
					node_id,
					commit_oid: self.commit_oid,
					commit_time: self.commit_time,
					tree_oid,
					link_count,
				});
				node_attr.set_mode(fuse::FileMode::S_IFDIR | 0o755);
				node_attr.set_size(4096);
				node_attr.set_link_count(link_count);
				fuse_vfs::LookupResult::found(node, node_attr)
			},
			EntryObject::Blob(blob_oid, blob_size) => {
				let node = Arc::new(GitBlobFile {
					repo: self.repo.clone(),
					node_id,
					blob_oid,
					blob_size,
					commit_time: self.commit_time,
					filemode: entry_filemode,
				});
				let perm = (entry_filemode as u32) & 0o777;
				node_attr.set_mode(fuse::FileMode::S_IFREG | perm);
				node_attr.set_link_count(1);
				node_attr.set_size(blob_size);
				fuse_vfs::LookupResult::found(node, node_attr)
			},
		};
		result.entry_cache_timeout = Duration::MAX;
		result.attr_cache_timeout = Duration::MAX;
		Ok(result)
	}

	fn opendir(
		&self,
		_header: &fuse::RequestHeader,
		_request: server::OpendirRequest<'_>,
	) -> Result<fuse_vfs::OpendirResult, fuse::Error> {
		let handle = Arc::new(GitTreeDirHandle {
			repo: self.repo.clone(),
			node_id_map: self.node_id_map.clone(),
			tree_oid: self.tree_oid,
		});
		Ok(fuse_vfs::OpendirResult::new(handle))
	}
}

// GitTreeDir }}}

// GitTreeDirHandle {{{

struct GitTreeDirHandle {
	repo: Arc<Mutex<git2::Repository>>,
	node_id_map: Arc<Mutex<GitNodeIdMap>>,
	tree_oid: git2::Oid,
}


impl fuse_vfs::DirectoryHandle for GitTreeDirHandle {
	fn as_readdir_handle(&self) -> Option<&dyn fuse_vfs::ReaddirHandle> {
		Some(self)
	}
}

impl fuse_vfs::ReaddirHandle for GitTreeDirHandle {
	fn readdir(
		&self,
		_header: &fuse::RequestHeader,
		request: server::ReaddirRequest<'_>,
	) -> Result<fuse_vfs::ReaddirResult, fuse::Error> {
		let size = cmp::min(request.size() as u32, i32::MAX as u32);
		let start_offset = request.offset().map_or(0, |o| o.get());

		let mut buf = vec![0u8; size as usize];
		let mut writer = server::ReaddirEntriesWriter::new(&mut buf);

		let repo = self.repo.lock().unwrap();
		let Ok(tree) = repo.find_tree(self.tree_oid) else {
			return Err(OsError::NOT_FOUND);
		};

		let mut next_offset = start_offset + 1;
		let mut node_id_map = self.node_id_map.lock().unwrap();
		for entry in tree.iter().skip(start_offset as usize) {
			let file_type = match entry.kind() {
				Some(git2::ObjectType::Tree) => fuse::FileType::Directory,
				Some(git2::ObjectType::Blob) => fuse::FileType::Regular,
				_ => continue,
			};
			let Ok(name) = NodeName::from_bytes(entry.name_bytes()) else {
				continue;
			};

			let offset = NonZeroU64::new(next_offset).unwrap();
			next_offset += 1;

			let entry_oid = entry.id();
			let node_id = node_id_map.ensure(NodeKey::OID(entry_oid));
			let mut dirent = server::ReaddirEntry::new(node_id, name, offset);
			dirent.set_file_type(file_type);
			if let Err(_) = writer.try_push(&dirent) {
				break;
			}
		}

		let buf_len = writer.position();
		buf.truncate(buf_len);
		Ok(fuse_vfs::ReaddirResult::new(buf))
	}
}

// }}}

// GitBlobFile {{{

struct GitBlobFile {
	repo: Arc<Mutex<git2::Repository>>,
	node_id: NodeId,
	blob_oid: git2::Oid,
	blob_size: u64,
	commit_time: fuse::UnixTime,
	filemode: i32,
}

impl fuse_vfs::Node for GitBlobFile {
	fn as_file(&self) -> Option<&dyn fuse_vfs::File> {
		Some(self)
	}

	fn getattr(
		&self,
		_header: &fuse::RequestHeader,
		_request: server::GetattrRequest<'_>,
	) -> Result<fuse_vfs::GetattrResult, fuse::Error> {
		let mut attr = fuse::NodeAttr::new(self.node_id);
		attr.set_user_id(getuid());
		attr.set_group_id(getgid());
		let perm = (self.filemode as u32) & 0o777;
		attr.set_mode(fuse::FileMode::S_IFREG | perm);
		attr.set_link_count(1);
		attr.set_size(self.blob_size);
		attr.set_ctime(self.commit_time);
		attr.set_mtime(self.commit_time);
		let mut result = fuse_vfs::GetattrResult::new(attr);
		result.cache_timeout = Duration::MAX;
		Ok(result)
	}
}

impl fuse_vfs::File for GitBlobFile {
	fn open(
		&self,
		_header: &fuse::RequestHeader,
		_request: server::OpenRequest<'_>,
	) -> Result<fuse_vfs::OpenResult, fuse::Error> {
		let handle = Arc::new(GitBlobOpenHandle {
			repo: self.repo.clone(),
			blob_oid: self.blob_oid,
		});
		Ok(fuse_vfs::OpenResult::new(handle))
	}
}

// GitBlobFile }}}

// GitBlobOpenHandle {{{

struct GitBlobOpenHandle {
	repo: Arc<Mutex<git2::Repository>>,
	blob_oid: git2::Oid,
}

impl fuse_vfs::FileHandle for GitBlobOpenHandle {
	fn as_read_handle(&self) -> Option<&dyn fuse_vfs::ReadHandle> {
		Some(self)
	}
}

impl fuse_vfs::ReadHandle for GitBlobOpenHandle {
	fn read(
		&self,
		_header: &fuse::RequestHeader,
		request: server::ReadRequest<'_>,
	) -> Result<fuse_vfs::ReadResult, fuse::Error> {
		let repo = self.repo.lock().unwrap();
		let Ok(blob) = repo.find_blob(self.blob_oid) else {
			return Err(OsError::NOT_FOUND);
		};

		let mut size = cmp::min(request.size() as u32, i32::MAX as u32);
		let offset = request.offset();

		let bytes = blob.content();
		if offset >= bytes.len() as u64 {
			return Ok(fuse_vfs::ReadResult::new(b""));
		}
		let avail = &bytes[offset as usize..];
		if size as usize > avail.len() {
			size = avail.len() as u32;
		}

		let mut buf = vec![0u8; size as usize];
		(&mut buf[..size as usize]).copy_from_slice(&avail[..size as usize]);
		Ok(fuse_vfs::ReadResult::new(buf))
	}
}

// GitBlobOpenHandle }}}

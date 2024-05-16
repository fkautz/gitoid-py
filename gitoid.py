# Copyright (c) 2024 gitoid-py authors.
# Original golang code: Copyright (c) 2022 Cisco and/or its affiliates.
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import argparse
import hashlib
import os
import sys
from typing import Optional, List, BinaryIO
from enum import Enum


class GitObjectType(Enum):
    BLOB = "blob"
    COMMIT = "commit"
    TAG = "tag"
    TREE = "tree"


class HashType(Enum):
    SHA1 = "sha1"
    SHA256 = "sha256"


class GitOID:
    """
    GitOID

    A class representing a Git object ID (OID).

    Methods
    -------
    __init__(git_object_type: GitObjectType, hash_name: HashType, hash_value: bytes)
        Initializes a new instance of the GitOID class.

    new(reader: BinaryIO, git_object_type: GitObjectType = GitObjectType.BLOB, content_length=None,
        hash_name=HashType.SHA1) -> GitOID
        Creates a new GitOID instance from a binary reader.

    header(git_object_type: GitObjectType, content_length: int) -> bytes
        Constructs the header of a Git object.

    __str__() -> str
        Returns the string representation of the GitOID.

    uri() -> str
        Returns the URI string representation of the GitOID.

    bytes() -> bytes
        Returns the hash value bytes of the GitOID.

    __eq__(other) -> bool
        Checks if the GitOID is equal to another GitOID.

    __repr__() -> str
        Returns the string representation of the GitOID object.

    from_uri(uri: str) -> GitOID
        Creates a GitOID instance from a URI string.

    match(reader: BinaryIO) -> bool
        Matches the GitOID with the binary reader content.

    find(paths: List[str]) -> Optional[str]
        Finds the first file matching the GitOID in the given list of paths.

    find_all(paths: List[str]) -> List[str]
        Finds all files matching the GitOID in the given list of paths.

    find_n(n: int, paths: List[str]) -> List[str]
        Finds the first n files matching the GitOID in the given list of paths.

    """
    def __init__(self, git_object_type: GitObjectType, hash_name: HashType, hash_value: bytes):
        self.git_object_type = git_object_type
        self.hash_name = hash_name
        self.hash_value = hash_value

    @classmethod
    def new(cls, reader: BinaryIO, git_object_type: GitObjectType = GitObjectType.BLOB, content_length=None,
            hash_name=HashType.SHA1) -> "GitOID":
        if reader is None:
            raise ValueError("reader may not be nil")

        # Default values
        if hash_name == HashType.SHA1:
            hash_func = hashlib.sha1()
        elif hash_name == HashType.SHA256:
            hash_func = hashlib.sha256()
        else:
            raise ValueError("hash_name must be sha1 or sha256")

        # Read content to compute content_length
        content = reader.read()
        seen_content_length = len(content)
        if content_length is not None:
            if seen_content_length != content_length:
                raise ValueError(f"content length mismatch: expected {content_length}, got {seen_content_length}")


        # Write the git object header
        hash_func.update(cls.header(git_object_type, seen_content_length))

        # Hash the content
        hash_func.update(content)

        return cls(git_object_type, hash_name, hash_func.digest())

    @staticmethod
    def header(git_object_type: GitObjectType, content_length: int) -> bytes:
        return f"{git_object_type.value} {content_length}\0".encode()

    def __str__(self) -> str:
        return self.hash_value.hex()

    def uri(self) -> str:
        return f"gitoid:{self.git_object_type.value}:{self.hash_name.value}:{str(self)}"

    def bytes(self) -> bytes:
        return self.hash_value

    def __eq__(self, other):
        if isinstance(other, GitOID):
            return self.hash_value == other.hash_value
        return False

    def __repr__(self):
        return f"<GitOID oid_value={self.uri()!r}>"

    @classmethod
    def from_uri(cls, uri: str) -> "GitOID":
        parts = uri.split(":")
        if len(parts) != 4 or parts[0] != "gitoid":
            raise ValueError(f"Invalid uri in gitoid.FromURI: {uri}")
        hash_value = bytes.fromhex(parts[3])
        return cls(GitObjectType(parts[1]), HashType(parts[2]), hash_value)

    def match(self, reader: BinaryIO) -> bool:
        other = GitOID.new(reader, self.git_object_type, hash_name=self.hash_name)
        return self == other

    def find(self, paths: List[str]) -> Optional[str]:
        found_files = self.find_n(1, paths)
        if found_files:
            return found_files[0]
        return None

    def find_all(self, paths: List[str]) -> List[str]:
        return self.find_n(0, paths)

    def find_n(self, n: int, paths: List[str]) -> List[str]:
        found_files = []
        for path in paths:
            for root, _, files in os.walk(path):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    with open(file_path, "rb") as file:
                        if self.match(file):
                            found_files.append(file_path)
                            if 0 < n == len(found_files):
                                return found_files
        return found_files


def main():
    parser = argparse.ArgumentParser(description="Compute gitoid of a file or stdin.")
    parser.add_argument(
        "-t", "--type", choices=["sha1", "sha256"], default="sha1",
        help="Hash type to use (default: sha1)."
    )
    parser.add_argument(
        "-f", "--file", type=str, help="File to read data from. If not specified, read from stdin."
    )
    args = parser.parse_args()

    hash_type = HashType(args.type)
    filename = args.file

    if filename:
        with open(filename, "rb") as file:
            gitoid_hash = GitOID.new(file, hash_name=hash_type, content_length=os.stat(filename).st_size)
    else:
        gitoid_hash = GitOID.new(sys.stdin.buffer, hash_name=hash_type)

    print(gitoid_hash.uri())


if __name__ == "__main__":
    main()

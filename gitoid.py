"""
gitoid-py

A python implementation of the gitoid library.
"""
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
    """
    Enum class representing the type of objects in Git.

    Each object type represents a different type of data stored in a Git repository.

    Attributes:
        BLOB (str): Represents a blob object in Git, which is used to store file data.
        COMMIT (str): Represents a commit object in Git, which is used to store the commit history.
        TAG (str): Represents a tag object in Git, which is used to tag a specific commit.
        TREE (str): Represents a tree object in Git, which is used to store the tree structure of
        the repository.

    Usage:
        ::

            # Access the GitObjectType enum values
            blob_type = GitObjectType.BLOB
            commit_type = GitObjectType.COMMIT
            tag_type = GitObjectType.TAG
            tree_type = GitObjectType.TREE

            # Get the string representation of an enum value
            blob_type_str = blob_type.value   # "blob"

            # Compare enum values
            is_blob_type = blob_type == GitObjectType.BLOB   # True

    Note:
        This class should be used to represent the object types in Git and should not be
        instantiated directly.
    """
    BLOB = "blob"
    COMMIT = "commit"
    TAG = "tag"
    TREE = "tree"


class HashType(Enum):
    """
    An enumeration class representing different hash types.

    Enum Values:
        - SHA1: Represents the SHA1 hash type.
        - SHA256: Represents the SHA256 hash type.
    """
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

    def __init__(self, git_object_type: GitObjectType, hash_name: HashType, hash_value):
        self.git_object_type = git_object_type
        self.hash_name = hash_name
        self.hash_value = hash_value

    @classmethod
    def new(cls,
            reader: BinaryIO,
            git_object_type: GitObjectType = GitObjectType.BLOB,
            content_length=None,
            hash_name=HashType.SHA1) -> "GitOID":
        """
        :param reader: A BinaryIO object containing the content of the git object.
        :param git_object_type: Optional. The type of the git object.
         Defaults to GitObjectType.BLOB.
        :param content_length: Optional. The expected length of the content.
        If provided, must match the actual length of the content.
        :param hash_name: The hashing algorithm to be used. Defaults to HashType.SHA1.
        :return: An instance of GitOID representing the hash of the git object.

        """
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
                raise ValueError(f"content length mismatch: expected {content_length}, "
                                 f"got {seen_content_length}")

        # Write the git object header
        hash_func.update(cls.header(git_object_type, seen_content_length))

        # Hash the content
        hash_func.update(content)

        return cls(git_object_type, hash_name, hash_func.digest())

    @staticmethod
    def header(git_object_type: GitObjectType, content_length: int):
        """
        :param git_object_type: The type of Git object to include in the header.
        :param content_length: The length of the content to be included in the header.
        :return: A byte string representing the header that includes the Git object type and
        content length.

        Example usage:
            git_object_type = GitObjectType.COMMIT
            content_length = 100
            header = MyClass.header(git_object_type, content_length)
        """
        return f"{git_object_type.value} {content_length}\0".encode()

    def __str__(self) -> str:
        """
        Returns the hexadecimal representation of the hash value.

        :return: A string containing the hexadecimal representation of the hash value.
        :rtype: str
        """
        return self.hash_value.hex()

    def uri(self) -> str:
        """
        Returns the URI in the format "gitoid:{git_object_type}:{hash_name}:{str_representation}".

        :return: The URI of the object.
        :rtype: str
        """
        return f"gitoid:{self.git_object_type.value}:{self.hash_name.value}:{str(self)}"

    def bytes(self) -> bytes:
        """
        Returns the hash value as a bytes object.

        :return: The hash value as a bytes object.
        """
        return self.hash_value

    def __eq__(self, other):
        """
        Check if this GitOID object is equal to another object.

        :param other: The object to compare with.
        :return: True if the GitOID object is equal to the other object, False otherwise.
        """
        if isinstance(other, GitOID):
            return self.hash_value == other.hash_value
        return False

    def __repr__(self):
        """
        Return the string representation of the GitOID object.

        :return: A string representation of the GitOID object.
        """
        return f"<GitOID oid_value={self.uri()!r}>"

    @classmethod
    def from_uri(cls, uri: str) -> "GitOID":
        """
        Create a GitOID object from a provided URI.

        :param uri: A URI in the format "gitoid:type:hash".
        :type uri: str
        :return: A GitOID object with the specified type and hash.
        :rtype: GitOID
        :raises ValueError: If the provided URI is invalid.
        """
        parts = uri.split(":")
        if len(parts) != 4 or parts[0] != "gitoid":
            raise ValueError(f"Invalid uri in gitoid.FromURI: {uri}")
        hash_value = bytes.fromhex(parts[3])
        return cls(GitObjectType(parts[1]), HashType(parts[2]), hash_value)

    def match(self, reader: BinaryIO) -> bool:
        """
        :param reader: A BinaryIO object representing the reader.
        :return: A boolean indicating if the current GitOID object matches the other GitOID object
        read from the given reader.

        This method takes in a BinaryIO object as a reader and compares the current GitOID object
        with the GitOID object read from the reader. It creates a new GitOID object called 'other'
        using the 'new' method of the GitOID class, passing in the reader, the git_object_type, and
        the hash_name as arguments. It then returns the result of the comparison between 'self' and
        'other' using the '==' operator.

        Example usage:
            with open('git_object.bin', 'rb') as file:
                matched = obj.match(file)
                if matched:
                    print("Objects match")
                else:
                    print("Objects do not match")
        """
        other = GitOID.new(reader, self.git_object_type, hash_name=self.hash_name)
        return self == other

    def find(self, paths: List[str]) -> Optional[str]:
        """
        :param paths: A list of file paths to search for.
        :return: The first file path found, or None if no files were found.
        """
        found_files = self.find_n(1, paths)
        if found_files:
            return found_files[0]
        return None

    def find_all(self, paths: List[str]) -> List[str]:
        """
        Find all occurrences of a given path.

        :param paths: A list of paths to search for.
        :type paths: List[str]
        :return: A list of all occurrences of the paths.
        :rtype: List[str]
        """
        return self.find_n(0, paths)

    def find_n(self, n: int, paths: List[str]) -> List[str]:
        """
        Find up to n files that match the given criteria in the specified paths.

        :param n: The maximum number of files to find.
        :param paths: A list of paths to search for files.
        :return: A list of file paths that match the specified criteria, with a maximum length of n.
        """
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
    """
    Main function to compute gitoid of a file or stdin.

    :return: None
    """
    parser = argparse.ArgumentParser(description="Compute gitoid of a file or stdin.")
    parser.add_argument(
        "-t", "--type", choices=["sha1", "sha256"], default="sha1",
        help="Hash type to use (default: sha1)."
    )
    parser.add_argument(
        "-f", "--file", type=str, help="File to read data from. "
                                       "If not specified, read from stdin."
    )
    args = parser.parse_args()

    hash_type = HashType(args.type)
    filename = args.file

    if filename:
        with open(filename, "rb") as file:
            gitoid_hash = GitOID.new(file,
                                     hash_name=hash_type,
                                     content_length=os.stat(filename).st_size)
    else:
        gitoid_hash = GitOID.new(sys.stdin.buffer, hash_name=hash_type)

    print(gitoid_hash.uri())


if __name__ == "__main__":
    main()

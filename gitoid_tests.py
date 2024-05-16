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

import os
import unittest
from io import BytesIO
from gitoid import GitOID, GitObjectType, HashType


class TestGitOID(unittest.TestCase):
    filename = "LICENSE"

    def test_gitoid_sha1(self):
        with open(self.filename, "rb") as file:
            gitoid_hash = GitOID.new(file)
            self.assertEqual(str(gitoid_hash), "261eeb9e9f8b2b4b0d119366dda99c6fd7d35c64")

    def test_gitoid_uri_sha1(self):
        with open(self.filename, "rb") as file:
            gitoid_hash = GitOID.new(file)
            self.assertEqual(gitoid_hash.uri(), "gitoid:blob:sha1:261eeb9e9f8b2b4b0d119366dda99c6fd7d35c64")

    def test_gitoid_bytes_sha1(self):
        input_data = b"example"
        gitoid_hash = GitOID.new(BytesIO(input_data))
        self.assertEqual(str(gitoid_hash), "96236f8158b12701d5e75c14fb876c4a0f31b963")

    def test_gitoid_sha1_content_length(self):
        with open(self.filename, "rb") as file:
            gitoid_hash = GitOID.new(file, git_object_type=GitObjectType.BLOB)
            self.assertEqual(str(gitoid_hash), "261eeb9e9f8b2b4b0d119366dda99c6fd7d35c64")

    def test_gitoid_sha1_content_length_with_explicit_length(self):
        with open(self.filename, "rb") as file:
            file_info = os.stat(self.filename)
            gitoid_hash = GitOID.new(file, git_object_type=GitObjectType.BLOB, content_length=file_info.st_size)
            self.assertEqual(str(gitoid_hash), "261eeb9e9f8b2b4b0d119366dda99c6fd7d35c64")

    def test_gitoid_sha1_content_length_error(self):
        with open(self.filename, "rb") as file:
            file_info = os.stat(self.filename)
            with self.assertRaises(ValueError):
                GitOID.new(file, git_object_type=GitObjectType.BLOB, content_length=file_info.st_size + 1)

    def test_gitoid_sha256(self):
        with open(self.filename, "rb") as file:
            gitoid_hash = GitOID.new(file, hash_name=HashType.SHA256)
            self.assertEqual(str(gitoid_hash), "ed43975fbdc3084195eb94723b5f6df44eeeed1cdda7db0c7121edf5d84569ab")

    def test_gitoid_uri_sha256(self):
        with open(self.filename, "rb") as file:
            gitoid_hash = GitOID.new(file, hash_name=HashType.SHA256)
            self.assertEqual(gitoid_hash.uri(), "gitoid:blob:sha256"
                                                ":ed43975fbdc3084195eb94723b5f6df44eeeed1cdda7db0c7121edf5d84569ab")

    def test_gitoid_bytes_sha256(self):
        input_data = b"example"
        gitoid_hash = GitOID.new(BytesIO(input_data), hash_name=HashType.SHA256)
        self.assertEqual(str(gitoid_hash), "b32d8f166adfa017e9cb0d57e0777f6e9b09aa3b03c84f8f98fc5995c5dcea9d")

    def test_gitoid_sha256_content_length_with_explicit_length(self):
        with open(self.filename, "rb") as file:
            file_info = os.stat(self.filename)
            gitoid_hash = GitOID.new(file,
                                     git_object_type=GitObjectType.BLOB,
                                     content_length=file_info.st_size,
                                     hash_name=HashType.SHA256)
            self.assertEqual(str(gitoid_hash), "ed43975fbdc3084195eb94723b5f6df44eeeed1cdda7db0c7121edf5d84569ab")

    def test_from_uri(self):
        with open(self.filename, "rb") as file:
            gitoid_hash = GitOID.new(file)

            gitoid_hash2 = GitOID.from_uri("gitoid:blob:sha1:261eeb9e9f8b2b4b0d119366dda99c6fd7d35c64")
            self.assertEqual(gitoid_hash, gitoid_hash2)

    def test_gitoid_equal_self(self):
        gitoid_hash = GitOID.from_uri("gitoid:blob:sha1:261eeb9e9f8b2b4b0d119366dda99c6fd7d35c64")
        gitoid_hash2 = gitoid_hash
        self.assertEqual(gitoid_hash, gitoid_hash2)

    def test_gitoid_equal_nil(self):
        gitoid_hash = GitOID.from_uri("gitoid:blob:sha1:261eeb9e9f8b2b4b0d119366dda99c6fd7d35c64")
        self.assertIsNotNone(gitoid_hash)

    def test_gitoid_match_match(self):
        with open(self.filename, "rb") as file:
            gitoid_hash = GitOID.new(file)

            with open(self.filename, "rb") as matching_file:
                self.assertTrue(gitoid_hash.match(matching_file))

    def test_gitoid_match_nomatch(self):
        with open(self.filename, "rb") as file:
            gitoid_hash = GitOID.new(file)

            does_not_match = BytesIO(b"does not match")
            self.assertFalse(gitoid_hash.match(does_not_match))

    def test_gitoid_find_found(self):
        with open(self.filename, "rb") as file:
            gitoid_hash = GitOID.new(file)

            found_file = gitoid_hash.find(["./testdata/FindTests"])
            if found_file:
                with open(found_file, "rb") as f:
                    self.assertTrue(gitoid_hash.match(f))

    def test_gitoid_find_notfound(self):
        gitoid_hash = GitOID.new(BytesIO(b"file not found"))
        found_file = gitoid_hash.find(["./testdata/FindTests"])
        self.assertIsNone(found_file)

    def test_gitoid_find_all_found(self):
        with open(self.filename, "rb") as file:
            gitoid_hash = GitOID.new(file)

            found_files = gitoid_hash.find_all(["./testdata/FindTests"])
            self.assertEqual(len(found_files), 2)
            for found_file in found_files:
                with open(found_file, "rb") as f:
                    self.assertTrue(gitoid_hash.match(f))


if __name__ == "__main__":
    unittest.main()

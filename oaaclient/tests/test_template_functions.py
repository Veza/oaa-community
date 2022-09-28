"""
Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
"""

from oaaclient.templates import unique_strs

def test_unique_strs():
    input = ["str1", "str2", "str3"]
    assert unique_strs(input) == input

    input = ["STR1", "STR1", "STR2", "str3", "str1"]
    assert unique_strs(input) == ["STR1", "STR2", "str3"]

    assert unique_strs([]) == []
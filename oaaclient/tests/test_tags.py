"""
Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
"""

import pytest
from oaaclient.templates import Tag, OAATemplateException


def test_tag_init():
    new_tag = Tag("test", "value")
    assert new_tag is not None
    assert new_tag.key == "test"
    assert new_tag.value == "value"


def test_tag_characters():

    good_tag = Tag("lettér 123_", "letter.123@something.com,characters456@blah.com and space")
    assert good_tag.key == "lettér 123_"
    assert good_tag.value == "letter.123@something.com,characters456@blah.com and space"

    with pytest.raises(OAATemplateException) as e:
        Tag("illegal:value!")

    assert e is not None
    assert "Invalid characters in tag key" in e.value.message

    with pytest.raises(OAATemplateException) as e:
        Tag("goodkey", "bad!value*")

    assert e is not None
    assert "Invalid characters in tag value" in e.value.message


def test_tag_equality():

    tag_a = Tag("tagA", "valueA")
    tag_a_same = Tag("tagA", "valueA")
    tag_a_different = Tag("tagA")

    tag_b = Tag("tagB", "valueB")

    assert tag_a == tag_a_same
    assert tag_a != tag_a_different
    assert tag_a != tag_b

"""
Copyright 2022 Veza Technologies Inc.

Use of this source code is governed by a the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
"""

import logging
from logging import NullHandler

# add null handler if calling class isn't logging
logging.getLogger(__name__).addHandler(NullHandler())
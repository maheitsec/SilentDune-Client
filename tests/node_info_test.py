#
# Authors: Robert Abram <robert.abram@entpack.com>
#
# Copyright (C) 2015 EntPack
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import unittest

from utils.node_info import NodeInformation

# import pytest


class TestNodeInformation(unittest.TestCase):

    def test_node_info(self):
        """
        Test that the NodeInformation init process doesn't fail.
        :return:
        """

        node_info = NodeInformation()
        self.assertFalse(node_info.error)


if __name__ == '__main__':
    unittest.main()

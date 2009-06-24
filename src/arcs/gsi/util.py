#############################################################################
#
# Copyright (c) 2009 Victorian Partnership for Advanced Computing Ltd and
# Contributors.
# All Rights Reserved.
#
# This program is free software: you can redistribute it and/or modify
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
#############################################################################

from M2Crypto import X509
MBSTRING_ASC  = 0x1000 | 1

def _build_name_from_string(dn):
    x509Name = X509.X509_Name()
    splitchar = ','
    if dn.startswith('/'):
        splitchar = '/'
    for entry in dn.split(splitchar):
        l = entry.split("=")
        x509Name.add_entry_by_txt(field=str(l[0].strip()), type=MBSTRING_ASC,
                                      entry=str(l[1]),len=-1, loc=-1, set=0)
    return x509Name




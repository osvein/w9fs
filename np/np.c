/* np - w9fs network provider
 * Copyright (C) 2018  Oskar Sveinsen
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include	<npapi.h>

const DWORD	caps[]	= {
	[WNNC_SPEC_VERSION]	= WNNC_SPEC_VERSION51,
	[WNNC_NET_TYPE]	= WNNC_NET_RDR2SAMPLE,
	[WNNC_DRIVER_VERSION]	= 0,
	[WNNC_USER]	= 0,
	[WNNC_CONNECTION]	= 0,
	[WNNC_DIALOG]	= 0,
	[WNNC_ADMIN]	= 0,
	[WNNC_ENUMERATION]	= 0,
	[WNNC_START]	= 0
};

DWORD APIENTRY
NPGetCaps(DWORD type)
{
	return type < sizeof(caps) / sizeof(*caps) ? caps[type] : 0;
}

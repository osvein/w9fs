/* fcall - interface to Plan 9 File protocol
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

#define	VERSION9P	"9P2000"

typedef	uint16_t	Tag;
typedef	uint32_t	Fid;
typedef	struct {
	uint8_t	type;
	uint32_t	vers;
	uint64_t	path;
} Qid;

typedef	struct {
	uint32_t	msize;
	char	*version;
} Ftversion, Frversion;

typedef	struct {
	Fid	afid;
	char	*uname;
	char	*aname;
} Ftauth, Ftattach;

typedef	struct {
	Qid	qid;
} Frauth;

typedef	struct {
	char *ename;
} Frerror;

typedef	struct {
	Tag	oldtag;
} Ftflush;

typedef	struct {
	Qid	aqid;
} Frattach;

typedef	struct {
	Fid	newfid;
	uint16_t	nwname;
	char	**wname;
} Ftwalk;

typedef	struct {
	uint16_t	nwqid;
	Qid	*qid;
} Frwalk;

typedef	struct {
	uint8_t	mode;
} Ftopen;

typedef	struct {
	Qid	qid;
	uint32_t	iounit;
} Fropen, Frcreate;

typedef	struct {
	char	*name;
	uint32_t	perm;
	uint8_t	mode;
} Ftcreate;

typedef	struct {
	uint64_t	offset;
	uint32_t	count;
} Ftread;

typedef	struct {
	uint32_t	count;
	uint8_t	*data;
} Frread;

typedef	struct {
	uint64_t	offset;
	uint32_t	count;
	uint8_t	*data;
} Ftwrite;

typedef	struct {
	uint32_t	count;
} Frwrite;

typedef	struct {
	uint32_t	type;
	uint32_t	dev;
	Qid	qid;
	uint32_t	mode;
	uint32_t	atime;
	uint32_t	mtime;
	uint64_t	length;
	char	*name;
	char	*uid;
	char	*gid;
	char	*muid;
} Ftwstat, Frwstat;

/*
typedef	struct {
} Fterror, Frflush, Ftclunk, Frclunk, Ftremove, Frremove, Ftstat, Frwstat;
*/

typedef	struct {
	uint8_t	type;
	Tag	tag;
	Fid	fid;
	union {
#define	F(type)	F##type	type
		F(tversion);
		F(rversion);
		F(tauth);
		F(rauth);
/*		F(terror);
*/		F(rerror);
		F(tflush);
/*		F(rflush);
*/		F(tattach);
		F(rattach);
		F(twalk);
		F(rwalk);
		F(topen);
		F(ropen);
		F(tcreate);
		F(rcreate);
		F(tread);
		F(rread);
		F(twrite);
		F(rwrite);
/*		F(tclunk);
		F(rclunk);
		F(tremove);
		F(rremove);
		F(tstat);
*/		F(rstat);
		F(twstat);
/*		F(rwstat);
*/
#undef	F
	} p;
} Fcall;

#define	GBIT8(p)	((p)[0])
#define	GBIT16(p)	((p)[0]|((p)[1]<<8))
#define	GBIT32(p)	((p)[0]|((p)[1]<<8)|((p)[2]<<16)|((p)[3]<<24))
#define	GBIT64(p)	\
	((uint32_t)((p)[0]|((p)[1]<<8)|((p)[2]<<16)|((p)[3]<<24)) |\
	((uint64_t)((p)[4]|((p)[5]<<8)|((p)[6]<<16)|((p)[7]<<24)) << 32))

#define	PBIT8(p,v)	(p)[0]=(v)
#define	PBIT16(p,v)	(p)[0]=(v);(p)[1]=(v)>>8
#define	PBIT32(p,v)	(p)[0]=(v);(p)[1]=(v)>>8;(p)[2]=(v)>>16;(p)[3]=(v)>>24
#define	PBIT64(p,v)	\
	(p)[0]=(v);(p)[1]=(v)>>8;(p)[2]=(v)>>16;(p)[3]=(v)>>24;\
	(p)[4]=(v)>>32;(p)[5]=(v)>>40;(p)[6]=(v)>>48;(p)[7]=(v)>>56

#define	BIT8SZ	1
#define	BIT16SZ	2
#define	BIT32SZ	4
#define	BIT64SZ	8
#define	QIDSZ	(BIT8SZ+BIT32SZ+BIT64SZ)

/* STATFIXLEN includes leading 16-bit count */
/* The count, however, excludes itself; total size is BIT16SZ+count */
#define	STATFIXLEN	(BIT16SZ+QIDSZ+5*BIT16SZ+4*BIT32SZ+1*BIT64SZ)	/* amount of fixed length data in a stat buffer */

#define	NOTAG	(Tag)~0U	/* Dummy tag */
#define	NOFID	(Fid)~0U	/* Dummy fid */
#define	IOHDRSZ	24	/* ample room for Twrite/Rread header (iounit) */

enum {
	Tversion	= 100,
	Rversion,
	Tauth	= 102,
	Rauth,
	Tattach	= 104,
	Rattach,
	Terror	= 106,	/* illegal */
	Rerror,
	Tflush	= 108,
	Rflush,
	Twalk	= 110,
	Rwalk,
	Topen	= 112,
	Ropen,
	Tcreate	= 114,
	Rcreate,
	Tread	= 116,
	Rread,
	Twrite	= 118,
	Rwrite,
	Tclunk	= 120,
	Rclunk,
	Tremove	= 122,
	Rremove,
	Tstat	= 124,
	Rstat,
	Twstat	= 126,
	Rwstat,
	Tmax,
};

unsigned	convM2S(uint8_t*, unsigned, Fcall*);
unsigned	convS2M(Fcall*, uint8_t*, unsigned);
unsigned	sizeS2M(Fcall*);

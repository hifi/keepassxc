/*
 *  Copyright (C) 2017 Toni Spets <toni.spets@iki.fi>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef ASN1KEY_H
#define ASN1KEY_H

#include "OpenSSHKey.h"
#include <QtCore>

namespace SSHAgent {
    class ASN1Key;
}

class ASN1Key
{
public:
    static QList<QSharedPointer<OpenSSHKey>> parseDSA(QByteArray &ba);
    static QList<QSharedPointer<OpenSSHKey>> parseRSA(QByteArray &ba);

private:
    static const quint8 TAG_INT        = 0x02;
    static const quint8 TAG_SEQUENCE   = 0x30;
    static const quint8 KEY_ZERO       = 0x0;

    ASN1Key() { }
    static bool parseHeader(BinaryStream &stream, quint8 wantedType);
    static QByteArray calculateIqmp(QByteArray &p, QByteArray &q);

    static bool nextTag(BinaryStream &stream, quint8 &tag, quint32 &len);
    static bool readInt(BinaryStream &stream, QByteArray &target);
};

#endif // ASN1KEY_H

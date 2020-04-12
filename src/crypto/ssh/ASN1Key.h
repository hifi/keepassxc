/*
 *  Copyright (C) 2018 Toni Spets <toni.spets@iki.fi>
 *  Copyright (C) 2018 KeePassXC Team <team@keepassxc.org>
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

#ifndef KEEPASSXC_ASN1KEY_H
#define KEEPASSXC_ASN1KEY_H

#include <QtCore>
#include <QByteArray>

namespace ASN1Key
{
    bool parseDSA(QByteArray& ba, QList<QByteArray>& publicData, QList<QByteArray>& privateData);
    bool parsePrivateRSA(QByteArray& ba, QList<QByteArray>& publicData, QList<QByteArray>& privateData);
    bool parsePublicRSA(QByteArray& ba, QList<QByteArray>& publicData, QList<QByteArray>& privateData);
} // namespace ASN1Key

#endif // KEEPASSXC_ASN1KEY_H

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

#include "PEM.h"
#include "BinaryStream.h"
#include "ASN1Key.h"
#include "OpenSSHKey.h"

bool PEM::parse()
{
    QStringList rows = m_string.split(QRegExp("[\r\n]"), QString::SkipEmptyParts);

    QString begin = rows.first();
    QString end = rows.last();

    QRegExp beginEx("-----BEGIN (.+)-----");
    QRegExp endEx("-----END (.+)-----");

    if (!beginEx.exactMatch(begin) || !endEx.exactMatch(end))
        return false;

    if (beginEx.cap(1) != endEx.cap(1))
        return false;

    m_type = beginEx.cap(1);

    rows.removeFirst();
    rows.removeLast();

    m_data = QByteArray::fromBase64(rows.join("").toLatin1());

    return (m_data.length() > 0);
}

QString PEM::getType()
{
    return m_type;
}

QList<QSharedPointer<OpenSSHKey>> PEM::getKeys(const QString &passphrase)
{
    if (m_type == "DSA PRIVATE KEY") {
        return ASN1Key::parseDSA(m_data);
    } else if (m_type == "RSA PRIVATE KEY") {
        return ASN1Key::parseRSA(m_data);
    } else if (m_type == "OPENSSH PRIVATE KEY") {
        return OpenSSHKey::parse(m_data, passphrase);
    } else {
        qWarning() << "Unknown PEM key type" << m_type;
    }

    QList<QSharedPointer<OpenSSHKey>> noKeys;
    return noKeys;
}

/*
 *  Copyright (C) 2020 KeePassXC Team <team@keepassxc.org>
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

bool PEM::parse(const QByteArray& in)
{
    QString pem = QString::fromLatin1(in);
    QStringList rows = pem.split(QRegularExpression("(?:\r?\n|\r)"), QString::SkipEmptyParts);

    if (rows.length() < 3) {
        m_error = tr("Invalid key file, expecting an OpenSSH key");
        return false;
    }

    QString begin = rows.first();
    QString end = rows.last();

    QRegularExpressionMatch beginMatch = QRegularExpression("^-----BEGIN ([^\\-]+)-----$").match(begin);
    QRegularExpressionMatch endMatch = QRegularExpression("^-----END ([^\\-]+)-----$").match(end);

    if (!beginMatch.hasMatch() || !endMatch.hasMatch()) {
        m_error = tr("Invalid key file, expecting an OpenSSH key");
        return false;
    }

    if (beginMatch.captured(1) != endMatch.captured(1)) {
        m_error = tr("PEM boundary mismatch");
        return false;
    }

    m_type = beginMatch.captured(1);

    rows.removeFirst();
    rows.removeLast();

    QRegularExpression keyValueExpr = QRegularExpression("^([A-Za-z0-9-]+): (.+)$");

    do {
        QRegularExpressionMatch keyValueMatch = keyValueExpr.match(rows.first());

        if (!keyValueMatch.hasMatch()) {
            break;
        }

        m_options.insert(keyValueMatch.captured(1), keyValueMatch.captured(2));

        rows.removeFirst();
    } while (!rows.isEmpty());

    m_data = QByteArray::fromBase64(rows.join("").toLatin1());

    if (m_data.isEmpty()) {
        m_error = tr("Base64 decoding failed");
        return false;
    }

    return true;
}

QString PEM::type() const
{
    return m_type;
}

const QMap<QString, QString> PEM::options() const
{
    return m_options;
}

QByteArray PEM::data() const
{
    return m_data;
}

QString PEM::error() const
{
    return m_error;
}

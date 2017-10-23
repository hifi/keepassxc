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

#ifndef OPENSSHKEY_H
#define OPENSSHKEY_H

#include "BinaryStream.h"

namespace SSHAgent {
    class OpenSSHKey;
}

class OpenSSHKey
{
public:
    OpenSSHKey() { }

    bool parse(const QByteArray &in, const QString &passphrase = nullptr);

    QString getType();
    int getKeyLength();
    QString getFingerprint();
    QString getComment();
    QString getPublicKey();
    QString getErrorString();

    void setType(QString type);
    void setPublicData(QList<QByteArray> data);
    void setPrivateData(QList<QByteArray> data);
    void setComment(QString comment);

    bool readPublic(BinaryStream &stream);
    bool readPrivate(BinaryStream &stream);
    bool writePublic(BinaryStream &stream);
    bool writePrivate(BinaryStream &stream);
private:
    bool parsePEM(const QByteArray &in, QByteArray &out);

    QString m_type;
    QList<QByteArray> m_publicData;
    QList<QByteArray> m_privateData;
    QString m_comment;
    QString m_error;
};

#endif // OPENSSHKEY_H

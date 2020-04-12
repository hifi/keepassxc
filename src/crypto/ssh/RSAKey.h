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

#ifndef KEEPASSXC_RSAKEY_H
#define KEEPASSXC_RSAKEY_H

#include <QtCore>

class BinaryStream;

class RSAKey : public QObject
{
    Q_OBJECT
public:
    RSAKey() = default;
    RSAKey(const RSAKey& other);
    bool openKey();

    bool parsePKCS1PEM(const QByteArray& in);
    const QString fingerprint() const;
    QList<QByteArray> publicParts() const;
    QList<QByteArray> privateParts() const;

    const QString publicKey() const;
    const QString privateKey() const;

    void setPublicParts(const QList<QByteArray>& data);
    void setPrivateParts(const QList<QByteArray>& data);

    enum Type
    {
        Public,
        Private
    };

    static RSAKey generate(bool secure = true);
    static RSAKey restoreFromBinary(Type eType, const QByteArray& serialized);
    static QByteArray serializeToBinary(Type eType, const RSAKey& key);

    static const QString TYPE_RSA_PRIVATE;
    static const QString TYPE_RSA_PUBLIC;

private:
    QList<QByteArray> m_publicData;
    QList<QByteArray> m_privateData;
    QString m_error;
};

#endif

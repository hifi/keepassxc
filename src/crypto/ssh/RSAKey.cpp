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

#include "RSAKey.h"
#include "core/Tools.h"
#include "crypto/ssh/ASN1Key.h"
#include "crypto/ssh/BinaryStream.h"
#include "crypto/ssh/PEM.h"

#include <gcrypt.h>

namespace
{
    QPair<QString, QList<QByteArray>> binaryDeserialize(const QByteArray& serialized)
    {
        if (serialized.isEmpty()) {
            return {};
        }
        QBuffer buffer;
        buffer.setData(serialized);
        buffer.open(QBuffer::ReadOnly);
        BinaryStream stream(&buffer);
        QString type;
        stream.readString(type);
        QByteArray temp;
        QList<QByteArray> data;
        while (stream.readString(temp)) {
            data << temp;
        }
        return ::qMakePair(type, data);
    }

    QByteArray binarySerialize(const QString& type, const QList<QByteArray>& data)
    {
        if (type.isEmpty() && data.isEmpty()) {
            return {};
        }
        QByteArray buffer;
        BinaryStream stream(&buffer);
        stream.writeString(type);
        for (const QByteArray& part : data) {
            stream.writeString(part);
        }
        return buffer;
    }
} // namespace

const QString RSAKey::TYPE_RSA_PRIVATE = "RSA PRIVATE KEY";
const QString RSAKey::TYPE_RSA_PUBLIC = "RSA PUBLIC KEY";

RSAKey::RSAKey(const RSAKey& other)
    : QObject(nullptr)
    , m_publicData(other.m_publicData)
    , m_privateData(other.m_privateData)
{
}

bool RSAKey::parsePKCS1PEM(const QByteArray& in)
{
    PEM pem;

    if (!pem.parse(in)) {
        m_error = pem.error();
        return false;
    }

    if (!m_privateData.isEmpty()) {
        return true;
    }

    QByteArray rawData = pem.data();

    if (rawData.isEmpty()) {
        m_error = tr("No private key payload to decrypt");
        return false;
    }

    if (pem.type() == TYPE_RSA_PRIVATE) {
        if (!ASN1Key::parsePrivateRSA(rawData, m_publicData, m_privateData)) {
            m_error = tr("Decryption failed, wrong passphrase?");
            return false;
        }
    } else if (pem.type() == TYPE_RSA_PUBLIC) {
        if (!ASN1Key::parsePublicRSA(rawData, m_publicData, m_privateData)) {
            m_error = tr("Decryption failed, wrong passphrase?");
            return false;
        }
    } else {
        m_error = tr("Unsupported key type: %1").arg(pem.type());
        return false;
    }

    return true;
}

QList<QByteArray> RSAKey::publicParts() const
{
    return m_publicData;
}

QList<QByteArray> RSAKey::privateParts() const
{
    return m_privateData;
}

const QString RSAKey::fingerprint() const
{
    if (m_publicData.isEmpty()) {
        return {};
    }

    QByteArray publicKey;
    BinaryStream stream(&publicKey);

    stream.writeString(QString("ssh-rsa"));

    for (const QByteArray& ba : m_publicData) {
        stream.writeString(ba);
    }

    QByteArray rawHash = QCryptographicHash::hash(publicKey, QCryptographicHash::Sha256);
    return "SHA256:" + QString::fromLatin1(rawHash.toBase64(QByteArray::OmitTrailingEquals));
}

const QString RSAKey::publicKey() const
{
    if (m_publicData.isEmpty()) {
        return {};
    }

    QByteArray publicKey;
    BinaryStream stream(&publicKey);

    stream.writeString(QString("ssh-rsa"));

    for (QByteArray ba : m_publicData) {
        stream.writeString(ba);
    }

    return "ssh-rsa " + QString::fromLatin1(publicKey.toBase64());
}

const QString RSAKey::privateKey() const
{
    if (m_privateData.isEmpty()) {
        return {};
    }

    QByteArray privateKey;
    BinaryStream stream(&privateKey);

    stream.writeString(QString("ssh-rsa"));

    for (QByteArray ba : m_privateData) {
        stream.writeString(ba);
    }

    return "ssh-rsa " + QString::fromLatin1(privateKey.toBase64());
}

void RSAKey::setPublicParts(const QList<QByteArray>& data)
{
    m_publicData = data;
}

void RSAKey::setPrivateParts(const QList<QByteArray>& data)
{
    m_privateData = data;
}

RSAKey RSAKey::restoreFromBinary(Type type, const QByteArray& serialized)
{
    RSAKey key;
    auto data = binaryDeserialize(serialized);
    switch (type) {
    case Public:
        key.setPublicParts(data.second);
        break;
    case Private:
        key.setPrivateParts(data.second);
        break;
    }
    return key;
}

QByteArray RSAKey::serializeToBinary(Type type, const RSAKey& key)
{
    switch (type) {
    case Public:
        return binarySerialize("ssh-rsa", key.publicParts());
    case Private:
        return binarySerialize("ssh-rsa", key.privateParts());
    }
    return {};
}

RSAKey RSAKey::generate(bool secure)
{
    enum Index
    {
        Params,
        CombinedKey,
        PrivateKey,
        PublicKey,

        Private_N,
        Private_E,
        Private_D,
        Private_P,
        Private_Q,
        Private_U, // private key
        Public_N,
        Public_E,
    };

    Tools::Map<Index, gcry_mpi_t, &gcry_mpi_release> mpi;
    Tools::Map<Index, gcry_sexp_t, &gcry_sexp_release> sexp;
    gcry_error_t rc = GPG_ERR_NO_ERROR;
    rc = gcry_sexp_build(&sexp[Params],
                         NULL,
                         secure ? "(genkey (rsa (nbits 4:2048)))" : "(genkey (rsa (transient-key) (nbits 4:2048)))");
    if (rc != GPG_ERR_NO_ERROR) {
        qWarning() << "Could not create ssh key" << gcry_err_code(rc);
        return RSAKey();
    }

    rc = gcry_pk_genkey(&sexp[CombinedKey], sexp[Params]);
    if (rc != GPG_ERR_NO_ERROR) {
        qWarning() << "Could not create ssh key" << gcry_err_code(rc);
        return RSAKey();
    }

    sexp[PrivateKey] = gcry_sexp_find_token(sexp[CombinedKey], "private-key", 0);
    sexp[PublicKey] = gcry_sexp_find_token(sexp[CombinedKey], "public-key", 0);

    sexp[Private_N] = gcry_sexp_find_token(sexp[PrivateKey], "n", 1);
    mpi[Private_N] = gcry_sexp_nth_mpi(sexp[Private_N], 1, GCRYMPI_FMT_USG);
    sexp[Private_E] = gcry_sexp_find_token(sexp[PrivateKey], "e", 1);
    mpi[Private_E] = gcry_sexp_nth_mpi(sexp[Private_E], 1, GCRYMPI_FMT_USG);
    sexp[Private_D] = gcry_sexp_find_token(sexp[PrivateKey], "d", 1);
    mpi[Private_D] = gcry_sexp_nth_mpi(sexp[Private_D], 1, GCRYMPI_FMT_USG);
    sexp[Private_Q] = gcry_sexp_find_token(sexp[PrivateKey], "q", 1);
    mpi[Private_Q] = gcry_sexp_nth_mpi(sexp[Private_Q], 1, GCRYMPI_FMT_USG);
    sexp[Private_P] = gcry_sexp_find_token(sexp[PrivateKey], "p", 1);
    mpi[Private_P] = gcry_sexp_nth_mpi(sexp[Private_P], 1, GCRYMPI_FMT_USG);
    sexp[Private_U] = gcry_sexp_find_token(sexp[PrivateKey], "u", 1);
    mpi[Private_U] = gcry_sexp_nth_mpi(sexp[Private_U], 1, GCRYMPI_FMT_USG);

    sexp[Public_N] = gcry_sexp_find_token(sexp[PublicKey], "n", 1);
    mpi[Public_N] = gcry_sexp_nth_mpi(sexp[Public_N], 1, GCRYMPI_FMT_USG);
    sexp[Public_E] = gcry_sexp_find_token(sexp[PublicKey], "e", 1);
    mpi[Public_E] = gcry_sexp_nth_mpi(sexp[Public_E], 1, GCRYMPI_FMT_USG);

    QList<QByteArray> publicParts;
    QList<QByteArray> privateParts;
    Tools::Buffer buffer;
    gcry_mpi_format format = GCRYMPI_FMT_USG;
    rc = gcry_mpi_aprint(format, &buffer.raw, &buffer.size, mpi[Private_N]);
    if (rc != GPG_ERR_NO_ERROR) {
        qWarning() << "Could not extract private key part" << gcry_err_code(rc);
        return RSAKey();
    }
    privateParts << buffer.content();

    buffer.clear();
    rc = gcry_mpi_aprint(format, &buffer.raw, &buffer.size, mpi[Private_E]);
    if (rc != GPG_ERR_NO_ERROR) {
        qWarning() << "Could not extract private key part" << gcry_err_code(rc);
        return RSAKey();
    }
    privateParts << buffer.content();

    buffer.clear();
    rc = gcry_mpi_aprint(format, &buffer.raw, &buffer.size, mpi[Private_D]);
    if (rc != GPG_ERR_NO_ERROR) {
        qWarning() << "Could not extract private key part" << gcry_err_code(rc);
        return RSAKey();
    }
    privateParts << buffer.content();

    buffer.clear();
    rc = gcry_mpi_aprint(format, &buffer.raw, &buffer.size, mpi[Private_U]);
    if (rc != GPG_ERR_NO_ERROR) {
        qWarning() << "Could not extract private key part" << gcry_err_code(rc);
        return RSAKey();
    }
    privateParts << buffer.content();

    buffer.clear();
    rc = gcry_mpi_aprint(format, &buffer.raw, &buffer.size, mpi[Private_P]);
    if (rc != GPG_ERR_NO_ERROR) {
        qWarning() << "Could not extract private key part" << gcry_err_code(rc);
        return RSAKey();
    }
    privateParts << buffer.content();

    buffer.clear();
    rc = gcry_mpi_aprint(format, &buffer.raw, &buffer.size, mpi[Private_Q]);
    if (rc != GPG_ERR_NO_ERROR) {
        qWarning() << "Could not extract private key part" << gcry_err_code(rc);
        return RSAKey();
    }
    privateParts << buffer.content();

    buffer.clear();
    rc = gcry_mpi_aprint(format, &buffer.raw, &buffer.size, mpi[Public_E]);
    if (rc != GPG_ERR_NO_ERROR) {
        qWarning() << "Could not extract public key part" << gcry_err_code(rc);
        return RSAKey();
    }
    publicParts << buffer.content();

    buffer.clear();
    rc = gcry_mpi_aprint(format, &buffer.raw, &buffer.size, mpi[Public_N]);
    if (rc != GPG_ERR_NO_ERROR) {
        qWarning() << "Could not extract public key part" << gcry_err_code(rc);
        return RSAKey();
    }
    publicParts << buffer.content();
    RSAKey key;
    key.setPublicParts(publicParts);
    key.setPrivateParts(privateParts);
    return key;
}


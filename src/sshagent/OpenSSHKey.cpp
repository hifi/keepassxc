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

#include "OpenSSHKey.h"
#include <QCryptographicHash>
#include <gcrypt.h>

// temp bcrypt_pbkdf.cpp
int bcrypt_pbkdf(const QByteArray &pass, const QByteArray &salt, QByteArray &key, quint32 rounds);

QString OpenSSHKey::getType()
{
    return m_type;
}

int OpenSSHKey::getKeyLength()
{
    if (m_type == "ssh-dss" && m_publicData.length() == 4) {
        return (m_publicData[0].length() - 1) * 8;
    } else if (m_type == "ssh-rsa" && m_publicData.length() == 2) {
        return (m_publicData[1].length() - 1) * 8;
    } else if (m_type.startsWith("ecdsa-sha2-") && m_publicData.length() == 2) {
        return (m_publicData[1].length() - 1) * 4;
    } else if (m_type == "ssh-ed25519" && m_publicData.length() == 1) {
        return m_publicData[0].length() * 8;
    }

    return 0;
}

QString OpenSSHKey::getFingerprint()
{
    QByteArray publicKey;
    BinaryStream stream(&publicKey);

    stream.writeString(m_type);

    for (QByteArray ba : m_publicData) {
        stream.writeString(ba);
    }

    QByteArray rawHash = QCryptographicHash::hash(publicKey, QCryptographicHash::Sha256);

    return "SHA256:" + QString::fromLatin1(rawHash.toBase64(QByteArray::OmitTrailingEquals));
}

QString OpenSSHKey::getComment()
{
    return m_comment;
}

QString OpenSSHKey::getPublicKey()
{
    QByteArray publicKey;
    BinaryStream stream(&publicKey);

    stream.writeString(m_type);

    for (QByteArray ba : m_publicData) {
        stream.writeString(ba);
    }

    return m_type + " " + QString::fromLatin1(publicKey.toBase64()) + " " + m_comment;
}

QString OpenSSHKey::getErrorString()
{
    return m_error;
}

void OpenSSHKey::setType(QString type)
{
    m_type = type;
}

void OpenSSHKey::setPublicData(QList<QByteArray> data)
{
    m_publicData = data;
}

void OpenSSHKey::setPrivateData(QList<QByteArray> data)
{
    m_privateData = data;
}

void OpenSSHKey::setComment(QString comment)
{
    m_comment = comment;
}

bool OpenSSHKey::parsePEM(const QByteArray &in, QByteArray &out)
{
    QString pem = QString::fromLatin1(in);
    QStringList rows = pem.split(QRegExp("[\r\n]"), QString::SkipEmptyParts);

    QString begin = rows.first();
    QString end = rows.last();

    QRegExp beginEx("-----BEGIN (.+)-----");
    QRegExp endEx("-----END (.+)-----");

    if (!beginEx.exactMatch(begin) || !endEx.exactMatch(end)) {
        m_error = "PEM header or footer missing, is this really an OpenSSH key file?";
        return false;
    }

    if (beginEx.cap(1) != endEx.cap(1)) {
        m_error = "PEM header/footer mismatch, possible garbage at the end of the file";
        return false;
    }

    if (beginEx.cap(1) != "OPENSSH PRIVATE KEY") {
        m_error = "This is not an OpenSSH key, only new type style keys are supported";
        return false;
    }

    rows.removeFirst();
    rows.removeLast();

    out = QByteArray::fromBase64(rows.join("").toLatin1());

    if (out.length() == 0) {
        m_error = "Base64 decoding failed";
        return false;
    }

    return true;
}

bool OpenSSHKey::parse(const QByteArray &in, const QString &passphrase)
{
    QByteArray data;
    QByteArray magic;
    QString cipherName;
    QString kdfName;
    QByteArray kdfOptions;
    quint32 numberOfKeys;
    QByteArray privateKeys;

    if (!parsePEM(in, data))
        return false;

    BinaryStream stream(&data);

    magic.resize(15);
    stream.read(magic);

    if (QString::fromLatin1(magic) != "openssh-key-v1") {
        m_error = "Key file magic header id invalid";
        return false;
    }

    stream.readString(cipherName);
    stream.readString(kdfName);
    stream.readString(kdfOptions);
    stream.read(numberOfKeys);

    if (numberOfKeys == 0) {
        m_error = "Found zero keys";
        return false;
    }

    for (quint32 i = 0; i < numberOfKeys; i++) {
        QByteArray publicKey;
        stream.readString(publicKey);

        if (i == 0) {
            BinaryStream publicStream(&publicKey);
            readPublic(publicStream);
        }
    }

    // padded list of keys
    stream.readString(privateKeys);
    BinaryStream keyStream(&privateKeys);

    QByteArray key;
    QByteArray decrypted;
    int keyLen, ivLen;
    int cipher = 0;
    int cipherMode;

    if (cipherName == "aes256-cbc") {
        keyLen = 32;
        ivLen = 16;
        cipher = GCRY_CIPHER_AES256;
        cipherMode = GCRY_CIPHER_MODE_CBC;
    } else if (cipherName != "none") {
        m_error = "Unknown cipher: " + cipherName;
        return false;
    }

    key.fill(0, keyLen + ivLen);

    if (kdfName == "bcrypt") {
        BinaryStream optionStream(&kdfOptions);

        QByteArray salt;
        quint32 rounds;

        optionStream.readString(salt);
        optionStream.read(rounds);

        QByteArray phraseData = passphrase.toLatin1();

        bcrypt_pbkdf(phraseData, salt, key, rounds);
    } else if (kdfName != "none") {
        m_error = "Unknown KDF: "  + kdfName;
        return false;
    }

    if (cipher > 0) {
        gcry_cipher_hd_t hd;

        gcry_cipher_open(&hd, cipher, cipherMode, 0);
        gcry_cipher_setkey(hd, key.data(), keyLen);
        gcry_cipher_setiv(hd, key.data() + keyLen, ivLen);

        decrypted.resize(privateKeys.length());

        gcry_cipher_decrypt(hd, decrypted.data(), decrypted.length(), privateKeys.data(), privateKeys.length());
        gcry_cipher_close(hd);

        keyStream.setData(&decrypted);
    }

    quint32 checkInt1;
    quint32 checkInt2;

    keyStream.read(checkInt1);
    keyStream.read(checkInt2);

    if (checkInt1 != checkInt2) {
        m_error = "Key decryption failed, wrong passphrase?";
        return false;
    }

    return readPrivate(keyStream);
}

bool OpenSSHKey::readPublic(BinaryStream &stream)
{
    m_publicData.clear();

    if (!stream.readString(m_type)) {
        m_error = "Unexpected EOF while reading public key";
        return false;
    }

    int keyParts;
    if (m_type == "ssh-dss") {
        keyParts = 4;
    } else if (m_type == "ssh-rsa") {
        keyParts = 2;
    } else if (m_type.startsWith("ecdsa-sha2-")) {
        keyParts = 2;
    } else if (m_type == "ssh-ed25519") {
        keyParts = 1;
    } else {
        m_error = "Unknown key type: " + m_type;
        return false;
    }

    for (int i = 0; i < keyParts; i++) {
        QByteArray t;

        if (!stream.readString(t)) {
            m_error = "Unexpected EOF while reading public key";
            return false;
        }

        m_publicData.append(t);
    }

    return true;
}

bool OpenSSHKey::readPrivate(BinaryStream &stream)
{
    m_privateData.clear();

    if (!stream.readString(m_type)) {
            m_error = "Unexpected EOF while reading private key";
            return false;
    }

    int keyParts;
    if (m_type == "ssh-dss") {
        keyParts = 5;
    } else if (m_type == "ssh-rsa") {
        keyParts = 6;
    } else if (m_type.startsWith("ecdsa-sha2-")) {
        keyParts = 3;
    } else if (m_type == "ssh-ed25519") {
        keyParts = 2;
    } else {
        m_error = "Unknown key type: " + m_type;
        return false;
    }

    for (int i = 0; i < keyParts; i++) {
        QByteArray t;

        if (!stream.readString(t)) {
            m_error = "Unexpected EOF while reading private key";
            return false;
        }

        m_privateData.append(t);
    }

    if (!stream.readString(m_comment)) {
        m_error = "Unexpected EOF while reading private key";
        return false;
    }

    return true;
}

bool OpenSSHKey::writePublic(BinaryStream &stream)
{
    if (m_publicData.length() == 0) {
        m_error = "Can't write public key as it is empty";
        return false;
    }

    if (!stream.writeString(m_type)) {
        m_error = "Unexpected EOF when writing public key";
        return false;
    }

    for (QByteArray t : m_publicData) {
        if (!stream.writeString(t)) {
            m_error = "Unexpected EOF when writing public key";
            return false;
        }
    }

    return true;
}

bool OpenSSHKey::writePrivate(BinaryStream &stream)
{
    if (m_privateData.length() == 0) {
        m_error = "Can't write private key as it is empty";
        return false;
    }

    if (!stream.writeString(m_type)) {
        m_error = "Unexpected EOF when writing private key";
        return false;
    }

    for (QByteArray t : m_privateData) {
        if (!stream.writeString(t)) {
            m_error = "Unexpected EOF when writing private key";
            return false;
        }
    }

    if (!stream.writeString(m_comment)) {
        m_error = "Unexpected EOF when writing private key";
        return false;
    }

    return true;
}

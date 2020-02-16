/*
 *  Copyright (C) 2017 Toni Spets <toni.spets@iki.fi>
 *  Copyright (C) 2017 KeePassXC Team <team@keepassxc.org>
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

#include "crypto/SymmetricCipher.h"
#include "crypto/ssh/PEM.h"
#include "crypto/ssh/ASN1Key.h"
#include "crypto/ssh/BinaryStream.h"

#include <QCryptographicHash>
#include <QRegularExpression>
#include <QStringList>

const QString OpenSSHKey::TYPE_DSA_PRIVATE = "DSA PRIVATE KEY";
const QString OpenSSHKey::TYPE_RSA_PRIVATE = "RSA PRIVATE KEY";
const QString OpenSSHKey::TYPE_OPENSSH_PRIVATE = "OPENSSH PRIVATE KEY";

// bcrypt_pbkdf.cpp
int bcrypt_pbkdf(const QByteArray& pass, const QByteArray& salt, QByteArray& key, quint32 rounds);

OpenSSHKey::OpenSSHKey(QObject* parent)
    : QObject(parent)
    , m_type(QString())
    , m_cipherName(QString("none"))
    , m_kdfName(QString("none"))
    , m_kdfOptions(QByteArray())
    , m_rawType(QString())
    , m_rawData(QByteArray())
    , m_rawPublicData(QList<QByteArray>())
    , m_rawPrivateData(QByteArray())
    , m_comment(QString())
    , m_error(QString())
{
}

OpenSSHKey::OpenSSHKey(const OpenSSHKey& other)
    : QObject(nullptr)
    , m_type(other.m_type)
    , m_cipherName(other.m_cipherName)
    , m_kdfName(other.m_kdfName)
    , m_kdfOptions(other.m_kdfOptions)
    , m_rawType(other.m_rawType)
    , m_rawData(other.m_rawData)
    , m_rawPublicData(other.m_rawPublicData)
    , m_rawPrivateData(other.m_rawPrivateData)
    , m_comment(other.m_comment)
    , m_error(other.m_error)
{
}

bool OpenSSHKey::operator==(const OpenSSHKey& other) const
{
    // close enough for now
    return (fingerprint() == other.fingerprint());
}

const QString OpenSSHKey::cipherName() const
{
    return m_cipherName;
}

const QString OpenSSHKey::type() const
{
    return m_type;
}

int OpenSSHKey::keyLength() const
{
    if (m_type == "ssh-dss" && m_rawPublicData.length() == 4) {
        return (m_rawPublicData[0].length() - 1) * 8;
    } else if (m_type == "ssh-rsa" && m_rawPublicData.length() == 2) {
        return (m_rawPublicData[1].length() - 1) * 8;
    } else if (m_type.startsWith("ecdsa-sha2-") && m_rawPublicData.length() == 2) {
        return (m_rawPublicData[1].length() - 1) * 4;
    } else if (m_type == "ssh-ed25519" && m_rawPublicData.length() == 1) {
        return m_rawPublicData[0].length() * 8;
    }
    return 0;
}

const QString OpenSSHKey::fingerprint(QCryptographicHash::Algorithm algo) const
{
    if (m_rawPublicData.isEmpty()) {
        return {};
    }

    QByteArray publicKey;
    BinaryStream stream(&publicKey);

    stream.writeString(m_type);

    for (const QByteArray& ba : m_rawPublicData) {
        stream.writeString(ba);
    }

    QByteArray rawHash = QCryptographicHash::hash(publicKey, algo);

    if (algo == QCryptographicHash::Md5) {
        QString md5Hash = QString::fromLatin1(rawHash.toHex());
        QStringList md5HashParts;
        for (int i = 0; i < md5Hash.length(); i += 2) {
            md5HashParts.append(md5Hash.mid(i, 2));
        }
        return "MD5:" + md5HashParts.join(':');
    } else if (algo == QCryptographicHash::Sha256) {
        return "SHA256:" + QString::fromLatin1(rawHash.toBase64(QByteArray::OmitTrailingEquals));
    }

    return "HASH:" + QString::fromLatin1(rawHash.toHex());
}

const QString OpenSSHKey::comment() const
{
    return m_comment;
}

const QString OpenSSHKey::publicKey() const
{
    if (m_rawPublicData.isEmpty()) {
        return {};
    }

    QByteArray publicKey;
    BinaryStream stream(&publicKey);

    stream.writeString(m_type);

    for (QByteArray ba : m_rawPublicData) {
        stream.writeString(ba);
    }

    return m_type + " " + QString::fromLatin1(publicKey.toBase64()) + " " + m_comment;
}

const QString OpenSSHKey::errorString() const
{
    return m_error;
}

void OpenSSHKey::setComment(const QString& comment)
{
    m_comment = comment;
}

void OpenSSHKey::clearPrivate()
{
    m_rawData.clear();
    m_rawPrivateData.clear();
}

bool OpenSSHKey::parsePKCS1PEM(const QByteArray& in)
{
    PEM pem;

    if (!pem.parse(in)) {
        m_error = pem.error();
        return false;
    }

    m_rawType = pem.type();

    if (pem.options().value("Proc-Type").compare("4,encrypted", Qt::CaseInsensitive) == 0) {
        m_kdfName = "md5";
        m_cipherName = pem.options().value("DEK-Info").section(",", 0, 0);
        m_cipherIV = QByteArray::fromHex(pem.options().value("DEK-Info").section(",", 1, 1).toLatin1());
    }

    if (m_rawType == TYPE_DSA_PRIVATE || m_rawType == TYPE_RSA_PRIVATE) {
        m_rawData = pem.data();
    } else if (m_rawType == TYPE_OPENSSH_PRIVATE) {
        QByteArray data = pem.data();
        BinaryStream stream(&data);

        QByteArray magic;
        magic.resize(15);

        if (!stream.read(magic)) {
            m_error = tr("Key file way too small.");
            return false;
        }

        if (QString::fromLatin1(magic) != "openssh-key-v1") {
            m_error = tr("Key file magic header id invalid");
            return false;
        }

        stream.readString(m_cipherName);
        stream.readString(m_kdfName);
        stream.readString(m_kdfOptions);

        quint32 numberOfKeys;
        stream.read(numberOfKeys);

        if (numberOfKeys == 0) {
            m_error = tr("Found zero keys");
            return false;
        }

        for (quint32 i = 0; i < numberOfKeys; ++i) {
            QByteArray publicKey;
            if (!stream.readString(publicKey)) {
                m_error = tr("Failed to read public key.");
                return false;
            }

            if (i == 0) {
                BinaryStream publicStream(&publicKey);
                if (!readPublic(publicStream)) {
                    return false;
                }
            }
        }

        // padded list of keys
        if (!stream.readString(m_rawData)) {
            m_error = tr("Corrupted key file, reading private key failed");
            return false;
        }
    } else {
        m_error = tr("Unsupported key type: %1").arg(m_rawType);
        return false;
    }

    // load private if no encryption
    if (!encrypted()) {
        return openKey();
    }

    return true;
}

bool OpenSSHKey::encrypted() const
{
    return (m_cipherName != "none");
}

bool OpenSSHKey::openKey(const QString& passphrase)
{
    QScopedPointer<SymmetricCipher> cipher;

    if (!m_rawPrivateData.isEmpty()) {
        return true;
    }

    if (m_rawData.isEmpty()) {
        m_error = tr("No private key payload to decrypt");
        return false;
    }

    if (m_cipherName.compare("aes-128-cbc", Qt::CaseInsensitive) == 0) {
        cipher.reset(new SymmetricCipher(SymmetricCipher::Aes128, SymmetricCipher::Cbc, SymmetricCipher::Decrypt));
    } else if (m_cipherName == "aes256-cbc" || m_cipherName.compare("aes-256-cbc", Qt::CaseInsensitive) == 0) {
        cipher.reset(new SymmetricCipher(SymmetricCipher::Aes256, SymmetricCipher::Cbc, SymmetricCipher::Decrypt));
    } else if (m_cipherName == "aes256-ctr" || m_cipherName.compare("aes-256-ctr", Qt::CaseInsensitive) == 0) {
        cipher.reset(new SymmetricCipher(SymmetricCipher::Aes256, SymmetricCipher::Ctr, SymmetricCipher::Decrypt));
    } else if (m_cipherName != "none") {
        m_error = tr("Unknown cipher: %1").arg(m_cipherName);
        return false;
    }

    if (m_kdfName == "bcrypt") {
        if (!cipher) {
            m_error = tr("Trying to run KDF without cipher");
            return false;
        }

        if (passphrase.isEmpty()) {
            m_error = tr("Passphrase is required to decrypt this key");
            return false;
        }

        BinaryStream optionStream(&m_kdfOptions);

        QByteArray salt;
        quint32 rounds;

        optionStream.readString(salt);
        optionStream.read(rounds);

        QByteArray decryptKey;
        decryptKey.fill(0, cipher->keySize() + cipher->blockSize());

        QByteArray phraseData = passphrase.toUtf8();
        if (bcrypt_pbkdf(phraseData, salt, decryptKey, rounds) < 0) {
            m_error = tr("Key derivation failed, key file corrupted?");
            return false;
        }

        QByteArray keyData, ivData;
        keyData.setRawData(decryptKey.data(), cipher->keySize());
        ivData.setRawData(decryptKey.data() + cipher->keySize(), cipher->blockSize());

        cipher->init(keyData, ivData);

        if (!cipher->init(keyData, ivData)) {
            m_error = cipher->errorString();
            return false;
        }
    } else if (m_kdfName == "md5") {
        if (m_cipherIV.length() < 8) {
            m_error = tr("Cipher IV is too short for MD5 kdf");
            return false;
        }

        QByteArray keyData;
        QByteArray mdBuf;
        do {
            QCryptographicHash hash(QCryptographicHash::Md5);
            hash.addData(mdBuf);
            hash.addData(passphrase.toUtf8());
            hash.addData(m_cipherIV.data(), 8);
            mdBuf = hash.result();
            keyData.append(mdBuf);
        } while (keyData.size() < cipher->keySize());

        if (keyData.size() > cipher->keySize()) {
            // If our key size isn't a multiple of 16 (e.g. AES-192 or something),
            // then we will need to truncate it.
            keyData.resize(cipher->keySize());
        }

        if (!cipher->init(keyData, m_cipherIV)) {
            m_error = cipher->errorString();
            return false;
        }
    } else if (m_kdfName != "none") {
        m_error = tr("Unknown KDF: %1").arg(m_kdfName);
        return false;
    }

    QByteArray rawData = m_rawData;

    if (cipher && cipher->isInitalized()) {
        bool ok = false;
        rawData = cipher->process(rawData, &ok);
        if (!ok) {
            m_error = tr("Decryption failed, wrong passphrase?");
            return false;
        }
    }

    if (m_rawType == TYPE_DSA_PRIVATE) {
        QList<QByteArray> rawPrivateData;

        if (!ASN1Key::parseDSA(rawData, m_rawPublicData, rawPrivateData)) {
            m_error = tr("Decryption failed, wrong passphrase?");
            return false;
        }

        m_type = "ssh-dss";
        m_comment = "";

        m_rawPrivateData.clear();
        BinaryStream rawPrivateDataStream(&m_rawPrivateData);

        for (QByteArray t : rawPrivateData) {
            rawPrivateDataStream.writeString(t);
        }

        return true;
    } else if (m_rawType == TYPE_RSA_PRIVATE) {
        QList<QByteArray> rawPrivateData;

        if (!ASN1Key::parsePrivateRSA(rawData, m_rawPublicData, rawPrivateData)) {
            m_error = tr("Decryption failed, wrong passphrase?");
            return false;
        }

        m_type = "ssh-rsa";
        m_comment = "";

        m_rawPrivateData.clear();
        BinaryStream rawPrivateDataStream(&m_rawPrivateData);

        for (QByteArray t : rawPrivateData) {
            rawPrivateDataStream.writeString(t);
        }

        return true;
    } else if (m_rawType == TYPE_OPENSSH_PRIVATE) {
        BinaryStream keyStream(&rawData);

        quint32 checkInt1;
        quint32 checkInt2;

        keyStream.read(checkInt1);
        keyStream.read(checkInt2);

        if (checkInt1 != checkInt2) {
            m_error = tr("Decryption failed, wrong passphrase?");
            return false;
        }

        return readPrivate(keyStream);
    }

    m_error = tr("Unsupported key type: %1").arg(m_rawType);
    return false;
}

bool OpenSSHKey::readPublic(BinaryStream& stream)
{
    m_rawPublicData.clear();

    if (!stream.readString(m_type)) {
        m_error = tr("Unexpected EOF while reading public key");
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
        m_error = tr("Unknown key type: %1").arg(m_type);
        return false;
    }

    for (int i = 0; i < keyParts; ++i) {
        QByteArray t;

        if (!stream.readString(t)) {
            m_error = tr("Unexpected EOF while reading public key");
            return false;
        }

        m_rawPublicData.append(t);
    }

    return true;
}

bool OpenSSHKey::readPrivate(BinaryStream& stream)
{
    m_rawPrivateData.clear();
    BinaryStream privateStream(&m_rawPrivateData);

    if (!stream.readString(m_type)) {
        m_error = tr("Unexpected EOF while reading private key");
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
    } else if (m_type == "sk-ecdsa-sha2-nistp256@openssh.com") {
        QByteArray t;

        for (int i = 0; i < 3; i++) {
            t.clear();

            if (!stream.readString(t)) {
                m_error = tr("Unexpected EOF while reading private key");
                return false;
            }

            privateStream.writeString(t);
        }

        quint8 flags;

        if (!stream.read(flags)) {
            m_error = tr("Unexpected EOF while reading private key");
            return false;
        }

        privateStream.write(flags);

        keyParts = 2; // FIXME: ugly
    } else {
        m_error = tr("Unknown key type: %1").arg(m_type);
        return false;
    }

    for (int i = 0; i < keyParts; ++i) {
        QByteArray t;

        if (!stream.readString(t)) {
            m_error = tr("Unexpected EOF while reading private key");
            return false;
        }

        privateStream.writeString(t);
    }

    if (!stream.readString(m_comment)) {
        m_error = tr("Unexpected EOF while reading private key");
        return false;
    }

    return true;
}

bool OpenSSHKey::writePublic(BinaryStream& stream)
{
    if (m_rawPublicData.isEmpty()) {
        m_error = tr("Can't write public key as it is empty");
        return false;
    }

    if (!stream.writeString(m_type)) {
        m_error = tr("Unexpected EOF when writing public key");
        return false;
    }

    for (QByteArray t : m_rawPublicData) {
        if (!stream.writeString(t)) {
            m_error = tr("Unexpected EOF when writing public key");
            return false;
        }
    }

    return true;
}

bool OpenSSHKey::writePrivate(BinaryStream& stream)
{
    if (m_rawPrivateData.isEmpty()) {
        m_error = tr("Can't write private key as it is empty");
        return false;
    }

    if (!stream.writeString(m_type)) {
        m_error = tr("Unexpected EOF when writing private key");
        return false;
    }

    if (!stream.write(m_rawPrivateData)) {
        m_error = tr("Unexpected EOF when writing private key");
        return false;
    }

    if (!stream.writeString(m_comment)) {
        m_error = tr("Unexpected EOF when writing private key");
        return false;
    }

    return true;
}

const QString& OpenSSHKey::privateType() const
{
    return m_rawType;
}

uint qHash(const OpenSSHKey& key)
{
    return qHash(key.fingerprint());
}

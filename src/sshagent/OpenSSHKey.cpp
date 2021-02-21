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

#include "ASN1Key.h"
#include "BinaryStream.h"
#include "core/Tools.h"
#include "crypto/SymmetricCipher.h"

#include <QCryptographicHash>
#include <QRegularExpression>
#include <QStringList>

#include <botan/pwdhash.h>

const QString OpenSSHKey::TYPE_DSA_PRIVATE = "DSA PRIVATE KEY";
const QString OpenSSHKey::TYPE_RSA_PRIVATE = "RSA PRIVATE KEY";
const QString OpenSSHKey::TYPE_OPENSSH_PRIVATE = "OPENSSH PRIVATE KEY";

OpenSSHKey::OpenSSHKey(QObject* parent)
    : QObject(parent)
    , m_type(QString())
    , m_cipherName(QString("none"))
    , m_kdfName(QString("none"))
    , m_kdfOptions(QByteArray())
    , m_rawType(QString())
    , m_rawData(QByteArray())
    , m_rawPublicData(QByteArray())
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

const QString OpenSSHKey::fingerprint(QCryptographicHash::Algorithm algo) const
{
    if (m_rawPublicData.isEmpty()) {
        return {};
    }

    QByteArray publicKey;
    BinaryStream stream(&publicKey);

    stream.writeString(m_type);
    stream.write(m_rawPublicData);

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
    stream.write(m_rawPublicData);

    return m_type + " " + QString::fromLatin1(publicKey.toBase64()) + " " + m_comment;
}

const QString OpenSSHKey::errorString() const
{
    return m_error;
}

void OpenSSHKey::setType(const QString& type)
{
    m_type = type;
}

void OpenSSHKey::setPublicData(const QByteArray& data)
{
    m_rawPublicData = data;
}

void OpenSSHKey::setPrivateData(const QByteArray& data)
{
    m_rawPrivateData = data;
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

bool OpenSSHKey::extractPEM(const QByteArray& in, QByteArray& out)
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

    m_rawType = beginMatch.captured(1);

    rows.removeFirst();
    rows.removeLast();

    QRegularExpression keyValueExpr = QRegularExpression("^([A-Za-z0-9-]+): (.+)$");
    QMap<QString, QString> pemOptions;

    do {
        QRegularExpressionMatch keyValueMatch = keyValueExpr.match(rows.first());

        if (!keyValueMatch.hasMatch()) {
            break;
        }

        pemOptions.insert(keyValueMatch.captured(1), keyValueMatch.captured(2));

        rows.removeFirst();
    } while (!rows.isEmpty());

    if (pemOptions.value("Proc-Type").compare("4,encrypted", Qt::CaseInsensitive) == 0) {
        m_kdfName = "md5";
        m_cipherName = pemOptions.value("DEK-Info").section(",", 0, 0);
        m_cipherIV = QByteArray::fromHex(pemOptions.value("DEK-Info").section(",", 1, 1).toLatin1());
    }

    out = QByteArray::fromBase64(rows.join("").toLatin1());

    if (out.isEmpty()) {
        m_error = tr("Base64 decoding failed");
        return false;
    }

    return true;
}

bool OpenSSHKey::parsePKCS1PEM(const QByteArray& in)
{
    QByteArray data;

    if (!extractPEM(in, data)) {
        return false;
    }

    if (m_rawType == TYPE_DSA_PRIVATE || m_rawType == TYPE_RSA_PRIVATE) {
        m_rawData = data;
    } else if (m_rawType == TYPE_OPENSSH_PRIVATE) {
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
    QScopedPointer<SymmetricCipher> cipher(new SymmetricCipher());

    if (!m_rawPrivateData.isEmpty()) {
        return true;
    }

    if (m_rawData.isEmpty()) {
        m_error = tr("No private key payload to decrypt");
        return false;
    }

    QByteArray rawData = m_rawData;

    if (m_cipherName != "none") {
        auto cipherMode = SymmetricCipher::stringToMode(m_cipherName);
        if (cipherMode == SymmetricCipher::InvalidMode) {
            m_error = tr("Unknown cipher: %1").arg(m_cipherName);
            return false;
        }

        QByteArray keyData, ivData;

        if (m_kdfName == "bcrypt") {
            if (passphrase.isEmpty()) {
                m_error = tr("Passphrase is required to decrypt this key");
                return false;
            }

            int keySize = cipher->keySize(cipherMode);
            int blockSize = 16;

            BinaryStream optionStream(&m_kdfOptions);

            QByteArray salt;
            quint32 rounds;

            optionStream.readString(salt);
            optionStream.read(rounds);

            QByteArray decryptKey(keySize + blockSize, '\0');
            try {
                auto baPass = passphrase.toUtf8();
                auto pwhash = Botan::PasswordHashFamily::create_or_throw("Bcrypt-PBKDF")->from_iterations(rounds);
                pwhash->derive_key(reinterpret_cast<uint8_t*>(decryptKey.data()),
                                   decryptKey.size(),
                                   baPass.constData(),
                                   baPass.size(),
                                   reinterpret_cast<const uint8_t*>(salt.constData()),
                                   salt.size());
            } catch (std::exception& e) {
                m_error = tr("Key derivation failed: %1").arg(e.what());
                return false;
            }

            keyData = decryptKey.left(keySize);
            ivData = decryptKey.right(blockSize);
        } else if (m_kdfName == "md5") {
            if (m_cipherIV.length() < 8) {
                m_error = tr("Cipher IV is too short for MD5 kdf");
                return false;
            }

            int keySize = cipher->keySize(cipherMode);

            QByteArray mdBuf;
            do {
                QCryptographicHash hash(QCryptographicHash::Md5);
                hash.addData(mdBuf);
                hash.addData(passphrase.toUtf8());
                hash.addData(m_cipherIV.data(), 8);
                mdBuf = hash.result();
                keyData.append(mdBuf);
            } while (keyData.size() < keySize);

            if (keyData.size() > keySize) {
                // If our key size isn't a multiple of 16 (e.g. AES-192 or something),
                // then we will need to truncate it.
                keyData.resize(keySize);
            }

            ivData = m_cipherIV;
        } else if (m_kdfName != "none") {
            m_error = tr("Unknown KDF: %1").arg(m_kdfName);
            return false;
        }

        // Initialize the cipher using the processed key and iv data
        if (!cipher->init(cipherMode, SymmetricCipher::Decrypt, keyData, ivData)) {
            m_error = tr("Failed to initialize cipher: %1").arg(cipher->errorString());
            return false;
        }
        // Decrypt the raw data, we do not use finish because padding is handled separately
        if (!cipher->process(rawData)) {
            m_error = tr("Decryption failed: %1").arg(cipher->errorString());
            return false;
        }
    }

    if (m_rawType == TYPE_DSA_PRIVATE) {
        if (!ASN1Key::parseDSA(rawData, *this)) {
            m_error = tr("Decryption failed, wrong passphrase?");
            return false;
        }

        return true;
    } else if (m_rawType == TYPE_RSA_PRIVATE) {
        if (!ASN1Key::parseRSA(rawData, *this)) {
            m_error = tr("Decryption failed, wrong passphrase?");
            return false;
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
    BinaryStream rawPublicDataStream(&m_rawPublicData);

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

        rawPublicDataStream.writeString(t);
    }

    return true;
}

bool OpenSSHKey::readPrivate(BinaryStream& stream)
{
    m_rawPrivateData.clear();
    BinaryStream rawPrivateDataStream(&m_rawPrivateData);

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

        rawPrivateDataStream.writeString(t);
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

    if (!stream.write(m_rawPublicData)) {
        m_error = tr("Unexpected EOF when writing public key");
        return false;
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

uint qHash(const OpenSSHKey& key)
{
    return qHash(key.fingerprint());
}

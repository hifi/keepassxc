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
#include <QDebug>
#include <QCryptographicHash> // or gcrypt?

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

    stream.writePack(m_type);

    foreach (QByteArray ba, m_publicData) {
        stream.writePack(ba);
    }

    QByteArray rawHash = QCryptographicHash::hash(publicKey, QCryptographicHash::Sha256);

    return "SHA256:" + QString::fromLatin1(rawHash.toBase64(QByteArray::OmitTrailingEquals));
}

QString OpenSSHKey::getComment()
{
    return m_comment;
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

QList<QSharedPointer<OpenSSHKey>> OpenSSHKey::parse(QByteArray &data)
{
    QList<QSharedPointer<OpenSSHKey>> sshKeys;
    QByteArray magic;
    QString cipherName;
    QString kdfName;
    QString kdfOptions;
    quint32 numberOfKeys;
    QByteArray privateKeys;

    BinaryStream stream(&data);

    magic.resize(15);
    stream.read(magic);

    if (QString::fromLatin1(magic) != "openssh-key-v1") {
        qWarning() << "magic" << magic;
        return sshKeys;
    }

    stream.readPack(cipherName);

    if (cipherName != "none") {
        qWarning() << "cipherName" << cipherName;
        return sshKeys;
    }

    stream.readPack(kdfName);

    if (kdfName != "none") {
        qWarning() << "kdfName" << cipherName;
        return sshKeys;
    }

    stream.readPack(kdfOptions);
    stream.read(numberOfKeys);

    for (quint32 i = 0; i < numberOfKeys; i++) {
        QByteArray publicKey;
        stream.readPack(publicKey);
        BinaryStream publicStream(&publicKey);

        OpenSSHKey *key = new OpenSSHKey();
        key->readPublic(publicStream);
        sshKeys.append(QSharedPointer<OpenSSHKey>(key));
    }

    // padded list of keys
    stream.readPack(privateKeys);

    BinaryStream keyStream(&privateKeys);

    quint32 checkInt1;
    quint32 checkInt2;

    keyStream.read(checkInt1);
    keyStream.read(checkInt2);

    if (checkInt1 != checkInt2) {
        qWarning() << "check integers don't match";
        return sshKeys;
    }

    for (quint32 i = 0; i < numberOfKeys; i++) {
        OpenSSHKey *key = sshKeys.at(i).data();
        key->readPrivate(keyStream);
    }

    return sshKeys;
}

bool OpenSSHKey::readPublic(BinaryStream &stream)
{
    int keyParts;
    m_publicData.clear();
    stream.readPack(m_type);

    if (m_type == "ssh-dss") {
        keyParts = 4;
    } else if (m_type == "ssh-rsa") {
        keyParts = 2;
    } else if (m_type.startsWith("ecdsa-sha2-")) {
        keyParts = 2;
    } else if (m_type == "ssh-ed25519") {
        keyParts = 1;
    } else {
        qWarning() << "Unknown OpenSSH public key type" << m_type;
        return false;
    }

    for (int i = 0; i < keyParts; i++) {
        QByteArray t;
        stream.readPack(t);
        m_publicData.append(t);
    }

    return true;
}

bool OpenSSHKey::readPrivate(BinaryStream &stream)
{
    int keyParts;
    m_privateData.clear();
    stream.readPack(m_type);

    if (m_type == "ssh-dss") {
        keyParts = 5;
    } else if (m_type == "ssh-rsa") {
        keyParts = 6;
    } else if (m_type.startsWith("ecdsa-sha2-")) {
        keyParts = 3;
    } else if (m_type == "ssh-ed25519") {
        keyParts = 2;
    } else {
        qWarning() << "Unknown OpenSSH key type" << m_type;
        return false;
    }

    for (int i = 0; i < keyParts; i++) {
        QByteArray t;
        stream.readPack(t);
        m_privateData.append(t);
    }

    stream.readPack(m_comment);

    return true;
}

bool OpenSSHKey::writePublic(BinaryStream &stream)
{
    if (m_publicData.length() == 0)
        return false;

    stream.writePack(m_type);

    foreach (QByteArray t, m_publicData) {
        stream.writePack(t);
    }

    return true;
}

bool OpenSSHKey::writePrivate(BinaryStream &stream)
{
    if (m_privateData.length() == 0)
        return false;

    stream.writePack(m_type);

    foreach (QByteArray t, m_privateData) {
        stream.writePack(t);
    }

    stream.writePack(m_comment);
    return true;
}

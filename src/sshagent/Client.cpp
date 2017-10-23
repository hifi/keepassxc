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

#include "Client.h"
#include "BinaryStream.h"
#include <QtNetwork>

QString Client::getEnvironmentSocketPath()
{
    auto env = QProcessEnvironment::systemEnvironment();

    if (env.contains("SSH_AUTH_SOCK")) {
        return env.value("SSH_AUTH_SOCK");
    }

    return ""; // should return null or not?
}

bool Client::addIdentity(OpenSSHKey &key, quint32 lifetime)
{
    QLocalSocket socket;
    BinaryStream stream(&socket);

    socket.connectToServer(m_socketPath);
    if (!socket.waitForConnected(500)) {
        return false;
    }

    QByteArray requestData;
    BinaryStream request(&requestData);

    request.write(lifetime > 0 ? SSH_AGENTC_ADD_ID_CONSTRAINED : SSH_AGENTC_ADD_IDENTITY);
    key.writePrivate(request);

    if (lifetime > 0) {
        request.write(SSH_AGENT_CONSTRAIN_LIFETIME);
        request.write(lifetime);
    }

    stream.writeString(requestData);
    stream.flush();

    QByteArray responseData;
    stream.read(responseData);

    if (responseData.length() < 1 || static_cast<quint8>(responseData[0]) != SSH_AGENT_SUCCESS)
        return false;

    return true;
}

QList<QSharedPointer<OpenSSHKey>> Client::getIdentities()
{
    QLocalSocket socket;
    BinaryStream stream(&socket);
    QList<QSharedPointer<OpenSSHKey>> list;

    socket.connectToServer(m_socketPath);
    if (!socket.waitForConnected(500)) {
        return list;
    }

    // write identities request
    QByteArray requestData;
    BinaryStream requestStream(&requestData);
    requestStream.write(SSH_AGENTC_REQUEST_IDENTITIES);

    stream.writeString(requestData);

    // read complete response packet
    QByteArray responseData;
    stream.readString(responseData);

    BinaryStream responseStream(&responseData);

    quint8 responseType;
    responseStream.read(responseType);

    if (responseType == SSH_AGENT_IDENTITIES_ANSWER) {
        quint32 numIdentities;
        responseStream.read(numIdentities);

        for (quint32 i = 0; i < numIdentities; i++) {
            QByteArray keyData;
            QString keyComment;

            responseStream.readString(keyData);
            responseStream.readString(keyComment);

            BinaryStream keyStream(&keyData);

            OpenSSHKey *key = new OpenSSHKey();

            if (key->readPublic(keyStream)) {
                key->setComment(keyComment);
                list.append(QSharedPointer<OpenSSHKey>(key));
            } else {
                delete key;
            }
        }
    }

    return list;
}

bool Client::removeIdentity(OpenSSHKey& key)
{
    QLocalSocket socket;
    BinaryStream stream(&socket);

    socket.connectToServer(m_socketPath);
    if (!socket.waitForConnected(500)) {
        return false;
    }

    QByteArray requestData;
    BinaryStream request(&requestData);

    QByteArray keyData;
    BinaryStream keyStream(&keyData);
    key.writePublic(keyStream);

    request.write(SSH_AGENTC_REMOVE_IDENTITY);
    request.writeString(keyData);

    stream.writeString(requestData);
    stream.flush();

    QByteArray responseData;
    stream.read(responseData);

    if (responseData.length() < 1 || static_cast<quint8>(responseData[0]) != SSH_AGENT_SUCCESS)
        return false;

    return true;
}

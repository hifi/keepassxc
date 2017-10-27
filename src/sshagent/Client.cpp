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

Client Client::m_instance;

Client::Client()
{
    m_socketPath = QProcessEnvironment::systemEnvironment().value("SSH_AUTH_SOCK");
}

Client* Client::instance()
{
    return &m_instance;
}

bool Client::hasAgent()
{
    return (m_socketPath.length() > 0);
}

bool Client::addIdentity(OpenSSHKey &key, quint32 lifetime, bool confirm)
{
    QLocalSocket socket;
    BinaryStream stream(&socket);

    socket.connectToServer(m_socketPath);
    if (!socket.waitForConnected(500)) {
        return false;
    }

    QByteArray requestData;
    BinaryStream request(&requestData);

    request.write((lifetime > 0 || confirm) ? SSH_AGENTC_ADD_ID_CONSTRAINED : SSH_AGENTC_ADD_IDENTITY);
    key.writePrivate(request);

    if (lifetime > 0) {
        request.write(SSH_AGENT_CONSTRAIN_LIFETIME);
        request.write(lifetime);
    }

    if (confirm) {
        request.write(SSH_AGENT_CONSTRAIN_CONFIRM);
    }

    stream.writeString(requestData);
    stream.flush();

    QByteArray responseData;
    stream.read(responseData);

    if (responseData.length() < 1 || static_cast<quint8>(responseData[0]) != SSH_AGENT_SUCCESS)
        return false;

    return true;
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

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

#ifndef CLIENT_H
#define CLIENT_H

#include <QtCore>
#include <QList>
#include "OpenSSHKey.h"

namespace SSHAgent {
    class Client;
}

class Client
{
public:
    static Client* instance();

    bool hasAgent();
    bool addIdentity(OpenSSHKey&, quint32 lifetime = 0, bool confirm = false);
    bool removeIdentity(OpenSSHKey&);

private:
    const quint8 SSH_AGENT_FAILURE              = 5;
    const quint8 SSH_AGENT_SUCCESS              = 6;
    const quint8 SSH_AGENTC_REQUEST_IDENTITIES  = 11;
    const quint8 SSH_AGENT_IDENTITIES_ANSWER    = 12;
    const quint8 SSH_AGENTC_ADD_IDENTITY        = 17;
    const quint8 SSH_AGENTC_REMOVE_IDENTITY     = 18;
    const quint8 SSH_AGENTC_ADD_ID_CONSTRAINED  = 25;

    const quint8 SSH_AGENT_CONSTRAIN_LIFETIME   = 1;
    const quint8 SSH_AGENT_CONSTRAIN_CONFIRM    = 2;

    Client();

    static Client m_instance;
    QString m_socketPath;
};

#endif // CLIENT_H

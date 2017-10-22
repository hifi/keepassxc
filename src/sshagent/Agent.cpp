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

#include "Agent.h"
#include "sshagent/PEM.h"
#include "sshagent/KeeAgentSettings.h"

Agent::Agent(DatabaseWidget *parent) : QObject(parent), m_widget(parent)
{
    connect(parent, SIGNAL(currentModeChanged(DatabaseWidget::Mode)), this, SLOT(databaseModeChanged(DatabaseWidget::Mode)));
    m_client = new Client();
}

Agent::~Agent()
{
    emit databaseModeChanged(DatabaseWidget::LockedMode);
    delete m_client;
}

void Agent::databaseModeChanged(DatabaseWidget::Mode mode)
{
    auto keys = getKeys(m_widget->database());

    if (mode == DatabaseWidget::LockedMode && m_sentKeys) {
        foreach (QSharedPointer<OpenSSHKey> e, keys) {
            m_client->removeIdentity(*e.data());
        }

        m_sentKeys = false;
    }

    if ((mode == DatabaseWidget::ViewMode
            || mode == DatabaseWidget::EditMode)
            && !m_sentKeys) {
        foreach (QSharedPointer<OpenSSHKey> e, keys) {
            m_client->addIdentity(*e.data());
        }

        m_sentKeys = true;
    }
}

QList<QSharedPointer<OpenSSHKey>> Agent::getKeys(Database *db)
{
    QList<QSharedPointer<OpenSSHKey>> keys;

    // find KeeAgent compatible entries (KeeAgent.settings)
    foreach (Entry *e, db->rootGroup()->entriesRecursive()) {

        if (!e->attachments()->hasKey("KeeAgent.settings"))
            continue;

        KeeAgentSettings settings;
        settings.fromXml(e->attachments()->value("KeeAgent.settings"));

        if (settings.allowUseOfSshKey()
                && settings.addAtDatabaseOpen()
                && settings.removeAtDatabaseClose()
                ) {

            if (settings.selectedType() == "attachment") {
                QByteArray keyData = e->attachments()->value(settings.attachmentName());
                PEM pem(keyData);
                pem.parse();
                keys.append(pem.getKeys(e->password()));
            } else if (settings.fileName().length() > 0) {
                QFile file(settings.fileName());
                if (file.open(QIODevice::ReadOnly)) {
                    PEM pem(file.readAll());
                    pem.parse();
                    keys.append(pem.getKeys(e->password()));
                }
            }
        }
    }

    return keys;
}

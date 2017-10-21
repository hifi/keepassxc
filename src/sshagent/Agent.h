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

#ifndef AGENT_H
#define AGENT_H

#include <QtCore>
#include <QObject>
#include "gui/DatabaseWidget.h"

#include "sshagent/Client.h"

class Agent : public QObject
{
    Q_OBJECT
public:
    explicit Agent(DatabaseWidget *parent);
    ~Agent();

signals:

private slots:
    void databaseModeChanged(DatabaseWidget::Mode mode);

private:
    QList<QSharedPointer<OpenSSHKey>> getKeys(Database*);

    Client* m_client;
    DatabaseWidget* m_widget;
    bool m_sentKeys;
};

#endif // AGENT_H

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

#ifndef KEEAGENTSETTINGS_H
#define KEEAGENTSETTINGS_H

#include <QtCore>
#include <QXmlStreamReader>

class KeeAgentSettings
{
public:
    KeeAgentSettings() { }
    KeeAgentSettings(const QByteArray &ba);

    bool fromXml(const QByteArray &ba);
    QByteArray toXml();

    bool allowUseOfSshKey();
    bool addAtDatabaseOpen();
    bool removeAtDatabaseClose();
    bool useConfirmConstraintWhenAdding();
    bool useLifetimeConstraintWhenAdding();
    int lifetimeConstraintDuration();

    QString selectedType();
    QString attachmentName();
    bool saveAttachmentToTempFile();
    QString fileName();

private:
    bool readBool(QXmlStreamReader &reader);
    int readInt(QXmlStreamReader &reader);

    bool m_allowUseOfSshKey;
    bool m_addAtDatabaseOpen;
    bool m_removeAtDatabaseClose;
    bool m_useConfirmConstraintWhenAdding;
    bool m_useLifetimeConstraintWhenAdding;
    int m_lifetimeConstraintDuration;

    // location
    QString m_selectedType;
    QString m_attachmentName;
    bool m_saveAttachmentToTempFile;
    QString m_fileName;
};

#endif // KEEAGENTSETTINGS_H

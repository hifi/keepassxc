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

#include "KeeAgentSettings.h"

KeeAgentSettings::KeeAgentSettings(const QByteArray &ba)
{
    fromXml(ba);
}

bool KeeAgentSettings::allowUseOfSshKey()
{
    return m_allowUseOfSshKey;
}

bool KeeAgentSettings::addAtDatabaseOpen()
{
    return m_addAtDatabaseOpen;
}

bool KeeAgentSettings::removeAtDatabaseClose()
{
    return m_removeAtDatabaseClose;
}

bool KeeAgentSettings::useConfirmConstraintWhenAdding()
{
    return m_useConfirmConstraintWhenAdding;
}

bool KeeAgentSettings::useLifetimeConstraintWhenAdding()
{
    return m_useLifetimeConstraintWhenAdding;
}

int KeeAgentSettings::lifetimeConstraintDuration()
{
    return m_lifetimeConstraintDuration;
}

QString KeeAgentSettings::selectedType()
{
    return m_selectedType;
}

QString KeeAgentSettings::attachmentName()
{
    return m_attachmentName;
}

bool KeeAgentSettings::saveAttachmentToTempFile()
{
    return m_saveAttachmentToTempFile;
}

QString KeeAgentSettings::fileName()
{
    return m_fileName;
}

bool KeeAgentSettings::readBool(QXmlStreamReader &reader)
{
    reader.readNext();
    bool ret = (reader.text() == "true");
    reader.readNext(); // tag end
    return ret;
}

int KeeAgentSettings::readInt(QXmlStreamReader &reader)
{
    reader.readNext();
    int ret = reader.text().toInt();
    reader.readNext(); // tag end
    return ret;
}

bool KeeAgentSettings::fromXml(const QByteArray &ba)
{
    QXmlStreamReader reader;
    reader.addData(ba);

    if (reader.error() || !reader.readNextStartElement())
        return false;

    if (reader.qualifiedName() != "EntrySettings")
        return false;

    while (!reader.error() && reader.readNextStartElement()) {
        if (reader.name() == "AllowUseOfSshKey") {
            m_allowUseOfSshKey = readBool(reader);
        } else if (reader.name() == "AddAtDatabaseOpen") {
            m_addAtDatabaseOpen = readBool(reader);
        } else if (reader.name() == "RemoveAtDatabaseClose") {
            m_removeAtDatabaseClose = readBool(reader);
        } else if (reader.name() == "UseConfirmConstraintWhenAdding") {
            m_useConfirmConstraintWhenAdding = readBool(reader);
        } else if (reader.name() == "UseLifetimeConstraintWhenAdding") {
            m_useLifetimeConstraintWhenAdding = readBool(reader);
        } else if (reader.name() == "LifetimeConstraintDuration") {
            m_lifetimeConstraintDuration = readInt(reader);
        } else if (reader.name() == "Location") {
            while (!reader.error() && reader.readNextStartElement()) {
                if (reader.name() == "SelectedType") {
                    reader.readNext();
                    m_selectedType = reader.text().toString();
                    reader.readNext();
                } else if (reader.name() == "AttachmentName") {
                    reader.readNext();
                    m_attachmentName = reader.text().toString();
                    reader.readNext();
                } else if (reader.name() == "SaveAttachmentToTempFile") {
                    m_saveAttachmentToTempFile = readBool(reader);
                } else if (reader.name() == "FileName") {
                    reader.readNext();
                    m_fileName = reader.text().toString();
                    reader.readNext();
                } else {
                    qWarning() << "Skipping location element" << reader.name();
                    reader.skipCurrentElement();
                }
            }
        } else {
            qWarning() << "Skipping element" << reader.name();
            reader.skipCurrentElement();
        }
    }

    return true;
}

/*
 *  Copyright (C) 2020 Team KeePassXC <team@keepassxc.org>
 *  Copyright (C) 2012 Felix Geyer <debfx@fobos.de>
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

#ifndef KEEPASSX_AUTOTYPESELECTDIALOG_H
#define KEEPASSX_AUTOTYPESELECTDIALOG_H

#include "autotype/AutoTypeMatch.h"
#include <QDialog>
#include <QTimer>

class Database;

namespace Ui
{
    class AutoTypeSelectDialog;
}

class AutoTypeSelectDialog : public QDialog
{
    Q_OBJECT

public:
    explicit AutoTypeSelectDialog(QWidget* parent = nullptr);
    void setMatchList(const QList<AutoTypeMatch>& matchList);
    void setDatabaseList(const QList<QSharedPointer<Database>>& dbs);

signals:
    void matchActivated(AutoTypeMatch match);

protected:
    bool eventFilter(QObject* obj, QEvent* event) override;
    void closeEvent(QCloseEvent* event) override;

private slots:
    void submitAutoTypeMatch(AutoTypeMatch match);
    void performSearch();
    void moveSelectionUp();
    void moveSelectionDown();
    void activateCurrentIndex();

private:
    enum Action {
        TYPE_SEQUENCE,
        TYPE_USERNAME,
        TYPE_PASSWORD,
        TYPE_TOTP,
        COPY_USERNAME,
        COPY_PASSWORD,
        COPY_TOTP
    };

    // For some reason QScopedPointer causes compiler errors here...
    QSharedPointer<Ui::AutoTypeSelectDialog> m_ui;

    QList<QSharedPointer<Database>> m_dbs;
    QList<AutoTypeMatch> m_originalMatches;
    QTimer m_searchTimer;
};

#endif // KEEPASSX_AUTOTYPESELECTDIALOG_H

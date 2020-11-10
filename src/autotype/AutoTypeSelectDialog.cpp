/*
 *  Copyright (C) 2020 KeePassXC Team <team@keepassxc.org>
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

#include "AutoTypeSelectDialog.h"
#include "ui_AutoTypeSelectDialog.h"

#include <QApplication>
#include <QCloseEvent>
#include <QShortcut>
#include <QSortFilterProxyModel>
#if QT_VERSION >= QT_VERSION_CHECK(5, 10, 0)
#include <QScreen>
#else
#include <QDesktopWidget>
#endif

#include "core/Config.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/EntrySearcher.h"
#include "gui/Icons.h"

AutoTypeSelectDialog::AutoTypeSelectDialog(QWidget* parent)
    : QDialog(parent)
    , m_ui(new Ui::AutoTypeSelectDialog())
{
    setAttribute(Qt::WA_DeleteOnClose);
    // Places the window on the active (virtual) desktop instead of where the main window is.
    setAttribute(Qt::WA_X11BypassTransientForHint);
    setWindowFlags(windowFlags() | Qt::WindowStaysOnTopHint);
    setWindowIcon(icons()->applicationIcon());

    m_ui->setupUi(this);

#if QT_VERSION >= QT_VERSION_CHECK(5, 10, 0)
    auto screen = QApplication::screenAt(QCursor::pos());
    if (!screen) {
        // screenAt can return a nullptr, default to the primary screen
        screen = QApplication::primaryScreen();
    }
    QRect screenGeometry = screen->availableGeometry();
#else
    QRect screenGeometry = QApplication::desktop()->availableGeometry(QCursor::pos());
#endif
    QSize size = config()->get(Config::GUI_AutoTypeSelectDialogSize).toSize();
    size.setWidth(qMin(size.width(), screenGeometry.width()));
    size.setHeight(qMin(size.height(), screenGeometry.height()));
    resize(size);

    // move dialog to the center of the screen
    auto screenCenter = screenGeometry.center();
    move(screenCenter.x() - (size.width() / 2), screenCenter.y() - (size.height() / 2));

    connect(m_ui->view, SIGNAL(matchActivated(AutoTypeMatch)), SLOT(submitAutoTypeMatch(AutoTypeMatch)));
    connect(m_ui->view, SIGNAL(rejected()), SLOT(reject()));

    m_ui->search->setFocus();
    m_ui->search->installEventFilter(this);

    m_searchTimer.setInterval(300);
    m_searchTimer.setSingleShot(true);

    m_ui->action->installEventFilter(this);
    m_ui->action->addItem("Type sequence", QVariant::fromValue(static_cast<int>(Action::TYPE_SEQUENCE)));
    m_ui->action->addItem("Type {USERNAME}", QVariant::fromValue(static_cast<int>(Action::TYPE_USERNAME)));
    m_ui->action->addItem("Type {PASSWORD}", QVariant::fromValue(static_cast<int>(Action::TYPE_PASSWORD)));

    connect(m_ui->search, SIGNAL(textChanged(QString)), &m_searchTimer, SLOT(start()));
    connect(m_ui->search, SIGNAL(returnPressed()), SLOT(activateCurrentIndex()));
    connect(&m_searchTimer, SIGNAL(timeout()), SLOT(performSearch()));

    connect(m_ui->filterRadio, &QRadioButton::toggled, this, [this](bool checked) {
        if (checked) {
            // Reset to original match list
            m_ui->view->setMatchList(m_originalMatches);
            performSearch();
            m_ui->search->setFocus();
        }
    });
    connect(m_ui->searchRadio, &QRadioButton::toggled, this, [this](bool checked) {
        if (checked) {
            performSearch();
            m_ui->search->setFocus();
        }
    });

    connect(m_ui->buttonBox, SIGNAL(rejected()), SLOT(reject()));
}

void AutoTypeSelectDialog::setMatchList(const QList<AutoTypeMatch>& matchList)
{
    m_originalMatches = matchList;
    m_ui->view->setMatchList(matchList);
    if (matchList.isEmpty()) {
        m_ui->searchRadio->setChecked(true);
    } else {
        m_ui->filterRadio->setChecked(true);
    }
}

void AutoTypeSelectDialog::setDatabaseList(const QList<QSharedPointer<Database>>& dbs)
{
    m_dbs = dbs;
}

void AutoTypeSelectDialog::submitAutoTypeMatch(AutoTypeMatch match)
{
    accept();
    emit matchActivated(match);
}

void AutoTypeSelectDialog::performSearch()
{
    if (m_ui->filterRadio->isChecked()) {
        m_ui->view->filterList(m_ui->search->text());
        return;
    }

    EntrySearcher searcher;
    QList<AutoTypeMatch> matches;
    if (!m_ui->search->text().isEmpty()) {
        for (const auto& db : m_dbs) {
            auto found = searcher.search(m_ui->search->text(), db->rootGroup());
            for (auto entry : found) {
                QSet<QString> sequences;
                auto defSequence = entry->effectiveAutoTypeSequence();
                if (!defSequence.isEmpty()) {
                    matches.append({entry, defSequence});
                    sequences << defSequence;
                }
                for (auto assoc : entry->autoTypeAssociations()->getAll()) {
                    if (!sequences.contains(assoc.sequence) && !assoc.sequence.isEmpty()) {
                        matches.append({entry, assoc.sequence});
                        sequences << assoc.sequence;
                    }
                }
            }
        }
    }

    m_ui->view->setMatchList(matches);
}

void AutoTypeSelectDialog::moveSelectionUp()
{
    auto current = m_ui->view->currentIndex();
    auto previous = current.sibling(current.row() - 1, 0);

    if (previous.isValid()) {
        m_ui->view->setCurrentIndex(previous);
    }
}

void AutoTypeSelectDialog::moveSelectionDown()
{
    auto current = m_ui->view->currentIndex();
    auto next = current.sibling(current.row() + 1, 0);

    if (next.isValid()) {
        m_ui->view->setCurrentIndex(next);
    }
}

void AutoTypeSelectDialog::activateCurrentIndex()
{
    auto match = m_ui->view->currentMatch();

    switch (m_ui->action->currentIndex()) {
        case static_cast<int>(Action::TYPE_USERNAME):
            match.second = QString("{USERNAME}");
            break;
        case static_cast<int>(Action::TYPE_PASSWORD):
            match.second = QString("{PASSWORD}");
            break;
        default:
            break;
    }

    submitAutoTypeMatch(match);
}

bool AutoTypeSelectDialog::eventFilter(QObject* obj, QEvent* event)
{
    if (event->type() == QEvent::KeyPress) {
        QKeyEvent* keyEvent = static_cast<QKeyEvent*>(event);
        switch (keyEvent->key()) {
        case Qt::Key_Up:
            if (obj == m_ui->search) {
                moveSelectionUp();
                return true;
            }
            break;
        case Qt::Key_Down:
            if (obj == m_ui->search) {
                moveSelectionDown();
                return true;
            }
            break;
        case Qt::Key_Escape:
            if (m_ui->search->text().isEmpty()) {
                reject();
            } else {
                m_ui->search->clear();
            }
            return true;
        case Qt::Key_Return:
        case Qt::Key_Enter:
            activateCurrentIndex();
            return true;
        default:
            break;
        }
    }
    return QDialog::eventFilter(obj, event);
}

void AutoTypeSelectDialog::closeEvent(QCloseEvent* event)
{
    config()->set(Config::GUI_AutoTypeSelectDialogSize, size());
    event->accept();
}

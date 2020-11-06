/*
 *  Copyright (C) 2015 David Wu <lightvector@gmail.com>
 *  Copyright (C) 2017 KeePassXC Team <team@keepassxc.org>
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

#include "AutoTypeMatchView.h"

#include "core/Entry.h"
#include "gui/Clipboard.h"
#include "gui/Icons.h"

#include <QAction>
#include <QHeaderView>
#include <QKeyEvent>
#include <QSortFilterProxyModel>

class CustomSortFilterProxyModel : public QSortFilterProxyModel
{
public:
    explicit CustomSortFilterProxyModel(QObject* parent = nullptr)
        : QSortFilterProxyModel(parent){};
    ~CustomSortFilterProxyModel() override = default;

    // Only search the first three columns (ie, ignore sequence column)
    bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override
    {
        auto index0 = sourceModel()->index(sourceRow, 0, sourceParent);
        auto index1 = sourceModel()->index(sourceRow, 1, sourceParent);
        auto index2 = sourceModel()->index(sourceRow, 2, sourceParent);

        return sourceModel()->data(index0).toString().contains(filterRegExp())
               || sourceModel()->data(index1).toString().contains(filterRegExp())
               || sourceModel()->data(index2).toString().contains(filterRegExp());
    }
};

AutoTypeMatchView::AutoTypeMatchView(QWidget* parent)
    : QTableView(parent)
    , m_model(new AutoTypeMatchModel(this))
    , m_sortModel(new CustomSortFilterProxyModel(this))
{
    m_sortModel->setSourceModel(m_model);
    m_sortModel->setDynamicSortFilter(true);
    m_sortModel->setSortLocaleAware(true);
    m_sortModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    m_sortModel->setFilterKeyColumn(-1);
    m_sortModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    setModel(m_sortModel);

    setAlternatingRowColors(true);
    setDragEnabled(false);
    setSortingEnabled(true);
    setCursor(Qt::PointingHandCursor);
    setSelectionBehavior(QAbstractItemView::SelectRows);
    setSelectionMode(QAbstractItemView::SingleSelection);
    setTabKeyNavigation(false);
    horizontalHeader()->setStretchLastSection(true);
    verticalHeader()->hide();

    setContextMenuPolicy(Qt::ActionsContextMenu);
    auto typeUsernameAction = new QAction(icons()->icon("auto-type"), tr("Type {USERNAME}"), this);
    auto typePasswordAction = new QAction(icons()->icon("auto-type"), tr("Type {PASSWORD}"), this);
    auto copyUsernameAction = new QAction(icons()->icon("username-copy"), tr("Copy &username"), this);
    auto copyPasswordAction = new QAction(icons()->icon("password-copy"), tr("Copy &password"), this);
    addAction(typeUsernameAction);
    addAction(typePasswordAction);
    addAction(copyUsernameAction);
    addAction(copyPasswordAction);

    connect(typeUsernameAction, &QAction::triggered, this, [this] { performSequence(QStringLiteral("{USERNAME}")); });
    connect(typePasswordAction, &QAction::triggered, this, [this] { performSequence(QStringLiteral("{PASSWORD}")); });
    connect(copyUsernameAction, SIGNAL(triggered()), this, SLOT(copyUsername()));
    connect(copyPasswordAction, SIGNAL(triggered()), this, SLOT(copyPassword()));

    connect(this, &QTableView::clicked, this, [this](const QModelIndex& index) {
        emit matchActivated(matchFromIndex(index));
    });
}

void AutoTypeMatchView::copyUsername()
{
    clipboard()->setText(currentMatch().first->username());
    emit rejected();
}

void AutoTypeMatchView::copyPassword()
{
    clipboard()->setText(currentMatch().first->password());
    emit rejected();
}

void AutoTypeMatchView::performSequence(const QString& sequence)
{
    auto match = currentMatch();
    match.second = sequence;
    emit matchActivated(match);
}

void AutoTypeMatchView::keyPressEvent(QKeyEvent* event)
{
    if ((event->key() == Qt::Key_Enter || event->key() == Qt::Key_Return) && currentIndex().isValid()) {
        emit matchActivated(matchFromIndex(currentIndex()));
    }

    QTableView::keyPressEvent(event);
}

void AutoTypeMatchView::setMatchList(const QList<AutoTypeMatch>& matches)
{
    m_model->setMatchList(matches);
    m_sortModel->setFilterWildcard({});
    if (matches.isEmpty()) {
        return;
    }

    horizontalHeader()->resizeSections(QHeaderView::ResizeToContents);

    QModelIndex index = m_sortModel->mapToSource(m_sortModel->index(0, 0));
    selectionModel()->setCurrentIndex(m_sortModel->mapFromSource(index),
                                      QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
}

void AutoTypeMatchView::filterList(const QString& filter)
{
    m_sortModel->setFilterWildcard(filter);
    setCurrentIndex(m_sortModel->index(0, 0));
}

AutoTypeMatch AutoTypeMatchView::currentMatch()
{
    QModelIndexList list = selectionModel()->selectedRows();
    if (list.size() == 1) {
        return m_model->matchFromIndex(m_sortModel->mapToSource(list.first()));
    }
    return {};
}

AutoTypeMatch AutoTypeMatchView::matchFromIndex(const QModelIndex& index)
{
    if (index.isValid()) {
        return m_model->matchFromIndex(m_sortModel->mapToSource(index));
    }
    return {};
}

void AutoTypeMatchView::currentChanged(const QModelIndex& current, const QModelIndex& previous)
{
    auto match = matchFromIndex(current);
    if (match.first) {
        bool noUsername = match.first->username().isEmpty();
        bool noPassword = match.first->password().isEmpty();
        auto acts = actions();
        Q_ASSERT(acts.size() >= 4);
        acts[0]->setDisabled(noUsername);
        acts[1]->setDisabled(noPassword);
        acts[2]->setDisabled(noUsername);
        acts[3]->setDisabled(noPassword);
    }
    QTableView::currentChanged(current, previous);
}

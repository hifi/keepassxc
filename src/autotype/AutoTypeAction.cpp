/*
 *  Copyright (C) 2021 Team KeePassXC <team@keepassxc.org>
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

#include "AutoTypeAction.h"

#include "core/Tools.h"

AutoTypeKey::AutoTypeKey(Qt::Key key, Qt::KeyboardModifiers modifiers)
    : key(key)
    , modifiers(modifiers)
{
}

AutoTypeKey::AutoTypeKey(const QChar& character, Qt::KeyboardModifiers modifiers)
    : character(character)
    , modifiers(modifiers)
{
}

bool AutoTypeKey::exec(AutoTypeExecutor* executor)
{
    return executor->execType(this);
}

AutoTypeDelay::AutoTypeDelay(int delayMs, bool setExecDelay)
    : delayMs(delayMs)
    , setExecDelay(setExecDelay)
{
}

bool AutoTypeDelay::exec(AutoTypeExecutor* executor)
{
    if (setExecDelay) {
        // Change the delay between actions
        executor->execDelayMs = delayMs;
    } else {
        // Pause execution
        Tools::wait(delayMs);
    }

    return true;
}

bool AutoTypeClearField::exec(AutoTypeExecutor* executor)
{
    return executor->execClearField(this);
}

bool AutoTypeBegin::exec(AutoTypeExecutor* executor)
{
    return executor->execBegin(this);
}

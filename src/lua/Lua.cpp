#include "Lua.h"
#include "LuaDatabase.h"
#include "core/Database.h"

#include <QApplication>

Lua::Lua(const QString& path, Database *db)
{
    m_L = luaL_newstate();
    luaL_openlibs(m_L);
    luaL_loadfile(m_L, path.toLatin1().data());

    LuaDatabase::Initialize(m_L);
    LuaGroup::Initialize(m_L);
    LuaEntry::Initialize(m_L);

    // evil test database push
    LuaDatabase::push(m_L, db);
    lua_setglobal(m_L, "db");

    if (lua_pcall(m_L, 0, 0, 0) != LUA_OK) {
        const char *error = lua_tostring(m_L, -1);
        fprintf(stderr, "Lua error: %s\n", error);
    }
}

Lua::~Lua()
{
    lua_close(m_L);
}

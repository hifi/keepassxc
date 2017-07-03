#ifndef KEEPASSXC_LUA_H
#define KEEPASSXC_LUA_H

#include <QApplication>
#include "core/Database.h"

extern "C"
{
    #include <lua.h>
    #include <lualib.h>
    #include <lauxlib.h>
}

class Lua
{
public:
    Lua(const QString&, Database *db);
    ~Lua();
private:
    lua_State *m_L;
};

#endif // KEEPASSXC_LUA_H

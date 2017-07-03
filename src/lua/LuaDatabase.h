#ifndef LUADATABASE_H
#define LUADATABASE_H

#include "Lua.h"
#include "LuaGroup.h"
#include "core/Database.h"

#include <QDebug>

class LuaDatabase
{
public:
    static void Initialize(lua_State *L)
    {
        static luaL_Reg methods[] = {
            { "uuid",       uuid },
            { "rootGroup",  rootGroup },
            { 0, 0 }
        };

        luaL_newlib(L, methods);
        luaL_newmetatable(L, "Database");
        lua_pushliteral(L, "__index");
        lua_pushvalue(L, -3);
        lua_rawset(L, -3);
        lua_pop(L, 2);
    }

    static void push(lua_State *L, Database *ptr)
    {
        *static_cast<void **>(lua_newuserdata(L, sizeof(void*))) = ptr;
        luaL_getmetatable(L, "Database");
        lua_setmetatable(L, -2);
    }

private:
    LuaDatabase() {}

    static Database *check(lua_State *L)
    {
        luaL_checkudata(L, 1, "Database");
        return *static_cast<Database **>(lua_touserdata(L, 1));
    }

    static int uuid(lua_State *L)
    {
        lua_pushstring(L, check(L)->uuid().toHex().toLatin1().data());
        return 1;
    }

    static int rootGroup(lua_State *L)
    {
        LuaGroup::push(L, check(L)->rootGroup());
        return 1;
    }
};

#endif // LUADATABASE_H

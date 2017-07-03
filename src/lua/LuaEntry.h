#ifndef LUAENTRY_H
#define LUAENTRY_H

#include "Lua.h"
#include "core/Entry.h"

#include <QDebug>

class LuaEntry
{
public:
    static void Initialize(lua_State *L)
    {
        static luaL_Reg methods[] = {
            { "uuid",       uuid },
            { "title",      title },
            { "url",        url },
            { "username",   username },
            { "password",   password },
            { "notes",      notes },
            { 0, 0 }
        };

        luaL_newlib(L, methods);
        luaL_newmetatable(L, "Entry");
        lua_pushliteral(L, "__index");
        lua_pushvalue(L, -3);
        lua_rawset(L, -3);
        lua_pop(L, 2);
    }

    static void push(lua_State *L, Entry *entry)
    {
        *static_cast<void **>(lua_newuserdata(L, sizeof(void*))) = entry;
        luaL_getmetatable(L, "Entry");
        lua_setmetatable(L, -2);
    }
private:
    LuaEntry() {}

    static Entry *check(lua_State *L)
    {
        luaL_checkudata(L, 1, "Entry");
        return *static_cast<Entry **>(lua_touserdata(L, 1));
    }

    static int uuid(lua_State *L)
    {
        lua_pushstring(L, check(L)->uuid().toHex().toLatin1().data());
        return 1;
    }

    static int title(lua_State *L)
    {
        lua_pushstring(L, check(L)->title().toLatin1().data());
        return 1;
    }

    static int url(lua_State *L)
    {
        lua_pushstring(L, check(L)->url().toLatin1().data());
        return 1;
    }

    static int username(lua_State *L)
    {
        lua_pushstring(L, check(L)->username().toLatin1().data());
        return 1;
    }

    static int password(lua_State *L)
    {
        lua_pushstring(L, check(L)->password().toLatin1().data());
        return 1;
    }

    static int notes(lua_State *L)
    {
        lua_pushstring(L, check(L)->notes().toLatin1().data());
        return 1;
    }
};


#endif // LUAENTRY_H

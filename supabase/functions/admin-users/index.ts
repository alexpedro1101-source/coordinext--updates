import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function json(status: number, payload: Record<string, unknown>) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" },
  });
}

function cleanUsername(value: unknown): string {
  return String(value ?? "").trim().toLowerCase().replace(/\s+/g, "");
}

function cleanEmail(value: unknown): string {
  return String(value ?? "").trim().toLowerCase();
}

function cleanEquipment(value: unknown): string {
  return String(value ?? "").trim().toUpperCase().replace(/\s+/g, "");
}

function dbRole(value: unknown): "admin" | "supervisor" | "operador" {
  const role = String(value ?? "operador").trim().toLowerCase();
  if (role === "admin" || role === "administrador" || role === "administrator") return "admin";
  if (role === "supervisor") return "supervisor";
  return "operador";
}

function validDate(value: unknown): string | null {
  const text = String(value ?? "").trim();
  if (!text) return null;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(text)) throw new Error("La fecha de vencimiento debe usar AAAA-MM-DD.");
  return text;
}

async function findAuthUserByEmail(admin: any, email: string) {
  let page = 1;
  while (page <= 10) {
    const { data, error } = await admin.auth.admin.listUsers({ page, perPage: 100 });
    if (error) throw error;
    const users = data?.users ?? [];
    const found = users.find((item: any) => cleanEmail(item.email) === email);
    if (found) return found;
    if (users.length < 100) break;
    page += 1;
  }
  return null;
}

async function audit(admin: any, actorId: string, action: string, detail: Record<string, unknown>) {
  const { error } = await admin.from("auditoria").insert({
    usuario_id: actorId,
    accion: action,
    detalle: detail,
  });
  if (error) console.error("No se pudo registrar auditoría", error.message);
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json(405, { ok: false, error: "Método no permitido." });

  try {
    const url = Deno.env.get("SUPABASE_URL") ?? "";
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
    if (!url || !serviceKey) return json(500, { ok: false, error: "Faltan secretos internos de Supabase." });

    const authorization = req.headers.get("Authorization") ?? "";
    const token = authorization.replace(/^Bearer\s+/i, "").trim();
    if (!token) return json(401, { ok: false, error: "Sesión no válida." });

    const admin = createClient(url, serviceKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const { data: userData, error: userError } = await admin.auth.getUser(token);
    const actor = userData?.user;
    if (userError || !actor) return json(401, { ok: false, error: "La sesión expiró. Ingrese nuevamente." });

    const { data: actorProfile, error: actorProfileError } = await admin
      .from("perfiles")
      .select("id, rol, activo")
      .eq("id", actor.id)
      .maybeSingle();
    if (actorProfileError) throw actorProfileError;
    if (!actorProfile?.activo || actorProfile.rol !== "admin") {
      return json(403, { ok: false, error: "Solo un administrador activo puede realizar esta operación." });
    }

    const body = await req.json().catch(() => ({}));
    const action = String(body?.action ?? "").trim().toLowerCase();

    if (action === "health") {
      return json(200, { ok: true, service: "admin-users", actor_id: actor.id });
    }

    if (action === "save_user") {
      const username = cleanUsername(body.usuario);
      const email = cleanEmail(body.correo);
      const name = String(body.nombre ?? "").trim();
      const role = dbRole(body.rol);
      const active = body.activo !== false;
      const expires = validDate(body.vence);
      const password = String(body.password ?? "");
      const requestedLegacyId = String(body.legacy_id ?? "").trim();
      const requestedProfileId = String(body.profile_id ?? "").trim();

      if (!/^[a-z0-9._-]{3,40}$/.test(username)) {
        return json(400, { ok: false, error: "El usuario debe tener entre 3 y 40 caracteres válidos." });
      }
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
        return json(400, { ok: false, error: "El correo no es válido." });
      }
      if (password && password.length < 8) {
        return json(400, { ok: false, error: "La contraseña debe tener al menos 8 caracteres." });
      }

      let controlRow: any = null;
      if (requestedLegacyId) {
        const { data, error } = await admin
          .from("usuarios_control")
          .select("legacy_id, profile_id, usuario, correo, sesion_version")
          .eq("legacy_id", requestedLegacyId)
          .maybeSingle();
        if (error) throw error;
        controlRow = data;
      }

      const { data: usernameConflict, error: usernameConflictError } = await admin
        .from("usuarios_control")
        .select("legacy_id")
        .eq("usuario", username)
        .maybeSingle();
      if (usernameConflictError) throw usernameConflictError;
      if (usernameConflict && usernameConflict.legacy_id !== requestedLegacyId) {
        return json(409, { ok: false, error: "Ese nombre de usuario ya existe." });
      }

      let authUser: any = null;
      const profileId = requestedProfileId || controlRow?.profile_id || "";
      if (profileId) {
        const { data, error } = await admin.auth.admin.getUserById(profileId);
        if (!error) authUser = data?.user ?? null;
      }
      if (!authUser) authUser = await findAuthUserByEmail(admin, email);

      if (!authUser) {
        if (password.length < 8) {
          return json(400, {
            ok: false,
            error: "La cuenta no existe en Authentication. Ingrese una contraseña temporal de al menos 8 caracteres.",
          });
        }
        const { data, error } = await admin.auth.admin.createUser({
          email,
          password,
          email_confirm: true,
          user_metadata: { nombre: name, usuario: username },
        });
        if (error) throw error;
        authUser = data.user;
      } else {
        const attributes: Record<string, unknown> = {
          email,
          email_confirm: true,
          user_metadata: { ...(authUser.user_metadata ?? {}), nombre: name, usuario: username },
        };
        if (password) attributes.password = password;
        const { data, error } = await admin.auth.admin.updateUserById(authUser.id, attributes);
        if (error) throw error;
        authUser = data.user;
      }

      const { error: profileError } = await admin.from("perfiles").upsert({
        id: authUser.id,
        nombre: name || username,
        rol: role,
        activo: active,
      }, { onConflict: "id" });
      if (profileError) throw profileError;

      const legacyId = requestedLegacyId || controlRow?.legacy_id || `USR-${crypto.randomUUID()}`;
      const sessionVersion = Number(controlRow?.sesion_version ?? 0) + (controlRow ? 1 : 0);
      const { error: controlError } = await admin.from("usuarios_control").upsert({
        legacy_id: legacyId,
        profile_id: authUser.id,
        usuario: username,
        correo: email,
        nombre: name || username,
        rol: role,
        activo: active,
        vence: expires,
        sesion_version: sessionVersion,
        origen: "panel_admin",
        actualizado_en: new Date().toISOString(),
      }, { onConflict: "legacy_id" });
      if (controlError) throw controlError;

      const equipment = Array.from(new Set((Array.isArray(body.equipos) ? body.equipos : [])
        .map(cleanEquipment).filter((item: string) => item.length >= 4)));

      if (equipment.length) {
        const equipmentRows = equipment.map((id: string) => ({
          id,
          nombre: id,
          estado: "autorizado",
          mensaje: "Autorizado desde el Panel de Control",
          origen: "panel_admin",
          actualizado_en: new Date().toISOString(),
        }));
        const { error } = await admin.from("equipos_control").upsert(equipmentRows, { onConflict: "id" });
        if (error) throw error;
      }

      const { error: deleteLinksError } = await admin
        .from("usuario_equipos")
        .delete()
        .eq("usuario_legacy_id", legacyId);
      if (deleteLinksError) throw deleteLinksError;

      if (equipment.length) {
        const links = equipment.map((id: string) => ({
          usuario_legacy_id: legacyId,
          equipo_id: id,
          activo: true,
        }));
        const { error } = await admin.from("usuario_equipos").insert(links);
        if (error) throw error;
      }

      await audit(admin, actor.id, controlRow ? "usuario_actualizado" : "usuario_creado", {
        legacy_id: legacyId,
        profile_id: authUser.id,
        usuario: username,
        correo: email,
        rol: role,
        activo: active,
        equipos: equipment,
      });

      return json(200, {
        ok: true,
        user: { legacy_id: legacyId, profile_id: authUser.id, usuario: username, correo: email },
      });
    }

    if (action === "set_active" || action === "close_sessions" || action === "delete_user") {
      const legacyId = String(body.legacy_id ?? "").trim();
      if (!legacyId) return json(400, { ok: false, error: "Falta legacy_id." });

      const { data: controlRow, error: controlError } = await admin
        .from("usuarios_control")
        .select("legacy_id, profile_id, usuario, correo, activo, sesion_version")
        .eq("legacy_id", legacyId)
        .maybeSingle();
      if (controlError) throw controlError;
      if (!controlRow) return json(404, { ok: false, error: "El usuario no existe." });

      if (action === "set_active") {
        const active = body.activo === true;
        const { error } = await admin.from("usuarios_control").update({
          activo: active,
          sesion_version: Number(controlRow.sesion_version ?? 0) + 1,
          actualizado_en: new Date().toISOString(),
        }).eq("legacy_id", legacyId);
        if (error) throw error;
        if (controlRow.profile_id) {
          const { error: profileError } = await admin.from("perfiles").update({ activo: active }).eq("id", controlRow.profile_id);
          if (profileError) throw profileError;
        }
        await audit(admin, actor.id, active ? "usuario_activado" : "usuario_bloqueado", { legacy_id: legacyId });
        return json(200, { ok: true });
      }

      if (action === "close_sessions") {
        const { error } = await admin.from("usuarios_control").update({
          sesion_version: Number(controlRow.sesion_version ?? 0) + 1,
          actualizado_en: new Date().toISOString(),
        }).eq("legacy_id", legacyId);
        if (error) throw error;
        await audit(admin, actor.id, "sesiones_cerradas", { legacy_id: legacyId });
        return json(200, { ok: true });
      }

      if (controlRow.profile_id === actor.id) {
        return json(400, { ok: false, error: "No puede eliminar la cuenta con la que inició sesión." });
      }

      const { error: deleteControlError } = await admin.from("usuarios_control").delete().eq("legacy_id", legacyId);
      if (deleteControlError) throw deleteControlError;
      if (controlRow.profile_id) {
        const { error: deleteAuthError } = await admin.auth.admin.deleteUser(controlRow.profile_id);
        if (deleteAuthError) throw deleteAuthError;
      }
      await audit(admin, actor.id, "usuario_eliminado", {
        legacy_id: legacyId,
        usuario: controlRow.usuario,
        correo: controlRow.correo,
      });
      return json(200, { ok: true });
    }

    return json(400, { ok: false, error: "Acción administrativa desconocida." });
  } catch (error) {
    console.error(error);
    const message = error instanceof Error ? error.message : String(error);
    return json(500, { ok: false, error: message || "Error interno." });
  }
});

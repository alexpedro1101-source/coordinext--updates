-- ============================================================
-- CoordiNext PRO AA v10.6.1 - Panel Web administrado por Supabase
-- Ejecutar una sola vez en Supabase > SQL Editor.
-- Puede ejecutarse nuevamente: es idempotente.
-- ============================================================

create extension if not exists pgcrypto;

-- Función usada por las políticas del panel.
create or replace function public.es_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.perfiles
    where id = auth.uid()
      and activo = true
      and rol::text = 'admin'
  );
$$;

grant execute on function public.es_admin() to authenticated;

-- Completar configuración global.
alter table public.configuracion_global
  add column if not exists sistema_activo boolean not null default true,
  add column if not exists archivo_actualizacion text,
  add column if not exists url_actualizacion text,
  add column if not exists version_publicada text,
  add column if not exists fecha_version date,
  add column if not exists cambios_version jsonb not null default '[]'::jsonb,
  add column if not exists origen_migracion text,
  add column if not exists actualizado_por uuid references public.perfiles(id) on delete set null;

insert into public.configuracion_global (id)
values (1)
on conflict (id) do nothing;

create table if not exists public.usuarios_control (
  legacy_id text primary key,
  profile_id uuid unique references public.perfiles(id) on delete set null,
  usuario text not null unique,
  correo text,
  nombre text,
  rol text not null default 'operador' check (rol in ('admin','supervisor','operador')),
  activo boolean not null default true,
  vence date,
  sesion_version integer not null default 0,
  origen text not null default 'panel_web',
  actualizado_en timestamptz,
  creado_en timestamptz not null default now()
);

create table if not exists public.equipos_control (
  id text primary key,
  nombre text,
  estado text not null default 'pendiente' check (estado in ('pendiente','autorizado','bloqueado')),
  vence date,
  mensaje text,
  version_app text,
  ultima_conexion timestamptz,
  origen text not null default 'panel_web',
  actualizado_en timestamptz,
  creado_en timestamptz not null default now()
);

create table if not exists public.usuario_equipos (
  usuario_legacy_id text not null references public.usuarios_control(legacy_id) on delete cascade,
  equipo_id text not null references public.equipos_control(id) on delete cascade,
  activo boolean not null default true,
  asignado_en timestamptz not null default now(),
  primary key (usuario_legacy_id,equipo_id)
);

create table if not exists public.acciones_soporte (
  legacy_id text primary key,
  equipo_id text not null default '*',
  equipo_nombre text,
  accion text not null,
  mensaje text,
  creada_en timestamptz,
  creada_por text,
  activa boolean not null default true,
  ejecutada_en timestamptz,
  resultado jsonb,
  creado_en timestamptz not null default now()
);

create table if not exists public.versiones_app (
  version text primary key,
  fecha date,
  archivo text,
  url_descarga text,
  cambios jsonb not null default '[]'::jsonb,
  obligatoria boolean not null default false,
  publicada boolean not null default true,
  origen text not null default 'panel_web',
  creado_en timestamptz not null default now()
);

create table if not exists public.directorios_documentos (
  slug text primary key,
  tipo text,
  version text,
  fecha_fuente timestamptz,
  fuente text,
  sha256 text,
  contenido jsonb not null,
  origen text not null default 'panel_web',
  actualizado_en timestamptz not null default now()
);

create table if not exists public.directorio_correos (
  id bigint generated always as identity primary key,
  conjunto text not null,
  version text,
  fuente text,
  nivel_1 text,
  nivel_2 text,
  nivel_3 text,
  nivel_4 text,
  nivel_5 text,
  ruta jsonb not null default '[]'::jsonb,
  ruta_texto text,
  correo text not null,
  activo boolean not null default true,
  importado_en timestamptz not null default now()
);

create index if not exists idx_usuarios_control_profile on public.usuarios_control(profile_id);
create index if not exists idx_usuarios_control_activo on public.usuarios_control(activo,vence);
create index if not exists idx_acciones_soporte_activas on public.acciones_soporte(activa,equipo_id,creada_en desc);
create index if not exists idx_directorio_correos_busqueda on public.directorio_correos(conjunto,nivel_1,nivel_2,nivel_3,nivel_4);
create index if not exists idx_directorio_correos_correo on public.directorio_correos(lower(correo));

alter table public.usuarios_control enable row level security;
alter table public.equipos_control enable row level security;
alter table public.usuario_equipos enable row level security;
alter table public.acciones_soporte enable row level security;
alter table public.versiones_app enable row level security;
alter table public.directorios_documentos enable row level security;
alter table public.directorio_correos enable row level security;

-- Recrear políticas del panel.
do $$
declare
  tab text;
begin
  foreach tab in array array['usuarios_control','equipos_control','usuario_equipos','acciones_soporte','versiones_app','directorios_documentos','directorio_correos']
  loop
    execute format('drop policy if exists %I on public.%I', tab || '_panel_admin', tab);
    execute format(
      'create policy %I on public.%I for all to authenticated using (public.es_admin()) with check (public.es_admin())',
      tab || '_panel_admin', tab
    );
  end loop;
end $$;

-- Las aplicaciones autenticadas necesitan leer el control, equipos, asignaciones, acciones, versiones y directorios.
drop policy if exists usuarios_control_lectura_app on public.usuarios_control;
create policy usuarios_control_lectura_app on public.usuarios_control for select to authenticated
using (profile_id = auth.uid() or public.es_admin() or exists(select 1 from public.perfiles p where p.id=auth.uid() and p.activo=true and p.rol::text='supervisor'));

drop policy if exists equipos_control_lectura_app on public.equipos_control;
create policy equipos_control_lectura_app on public.equipos_control for select to authenticated using (true);
drop policy if exists usuario_equipos_lectura_app on public.usuario_equipos;
create policy usuario_equipos_lectura_app on public.usuario_equipos for select to authenticated using (true);
drop policy if exists acciones_soporte_lectura_app on public.acciones_soporte;
create policy acciones_soporte_lectura_app on public.acciones_soporte for select to authenticated using (true);
drop policy if exists versiones_app_lectura_app on public.versiones_app;
create policy versiones_app_lectura_app on public.versiones_app for select to authenticated using (true);
drop policy if exists directorios_documentos_lectura_app on public.directorios_documentos;
create policy directorios_documentos_lectura_app on public.directorios_documentos for select to authenticated using (true);
drop policy if exists directorio_correos_lectura_app on public.directorio_correos;
create policy directorio_correos_lectura_app on public.directorio_correos for select to authenticated using (true);

-- Configuración global: lectura autenticada y administración desde el panel.
drop policy if exists configuracion_panel_admin on public.configuracion_global;
create policy configuracion_panel_admin on public.configuracion_global for all to authenticated
using (public.es_admin()) with check (public.es_admin());

-- Auditoría: administradores leen y registran.
drop policy if exists auditoria_panel_admin_leer on public.auditoria;
create policy auditoria_panel_admin_leer on public.auditoria for select to authenticated using (public.es_admin());
drop policy if exists auditoria_panel_admin_insertar on public.auditoria;
create policy auditoria_panel_admin_insertar on public.auditoria for insert to authenticated with check (usuario_id=auth.uid() and public.es_admin());

grant usage on schema public to authenticated;
grant select,insert,update,delete on public.configuracion_global to authenticated;
grant select,insert,update,delete on public.usuarios_control to authenticated;
grant select,insert,update,delete on public.equipos_control to authenticated;
grant select,insert,update,delete on public.usuario_equipos to authenticated;
grant select,insert,update,delete on public.acciones_soporte to authenticated;
grant select,insert,update,delete on public.versiones_app to authenticated;
grant select,insert,update,delete on public.directorios_documentos to authenticated;
grant select,insert,update,delete on public.directorio_correos to authenticated;
grant select,insert on public.auditoria to authenticated;
grant usage,select on all sequences in schema public to authenticated;

/tmp/apparmor-2.8.0/tests/regression/apparmor/dbus_service {
  dbus send bus=system path=/org/freedesktop/systemd1  interface=org.freedesktop.systemd1.Manager  member=LookupDynamicUserByName peer=( name=org.freedesktop.systemd1, label=unconfined),
}

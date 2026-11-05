#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/idarsi-activation-hook.XXXXXXXX")
[[ -n $tmp && -d $tmp && $tmp == "${TMPDIR:-/tmp}"/idarsi-activation-hook.* ]] || {
  printf 'Refusing unsafe temporary directory: %s\n' "$tmp" >&2
  exit 1
}
trap 'rm -rf -- "$tmp"' EXIT
# setup-venv writes under its repository root. Give it a disposable fixture so
# this test never mutates the shared repository .venv.
fixture="$tmp/repository"
mkdir -p "$fixture/scripts" "$fixture/environments"
cp "$repo_root/scripts/setup-venv" "$fixture/scripts/setup-venv"
cp "$repo_root/versions.yml" "$fixture/versions.yml"
for environment in ansible-min ansible-current ansible-next; do
  mkdir -p "$fixture/environments/$environment"
  cp "$repo_root/environments/$environment/requirements.txt" "$fixture/environments/$environment/requirements.txt"
  cp "$repo_root/environments/$environment/requirements.yml" "$fixture/environments/$environment/requirements.yml"
done
mkdir -p "$tmp/bin"
cat >"$tmp/bin/python3.9" <<'MOCK'
#!/usr/bin/env bash
if [[ $1 == -m && $2 == venv ]]; then
  destination=${@: -1}
  mkdir -p "$destination/bin"
  printf '#!/usr/bin/env bash\n' >"$destination/bin/activate"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$destination/bin/python"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$destination/bin/ansible-galaxy"
  chmod +x "$destination/bin/python" "$destination/bin/ansible-galaxy"
fi
MOCK
cat >"$tmp/bin/python3.12" <<'MOCK'
#!/usr/bin/env bash
if [[ $1 == -m && $2 == venv ]]; then
  destination=${@: -1}
  mkdir -p "$destination/bin"
  printf '#!/usr/bin/env bash\n' >"$destination/bin/activate"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$destination/bin/python"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$destination/bin/ansible-galaxy"
  chmod +x "$destination/bin/python" "$destination/bin/ansible-galaxy"
fi
MOCK
cat >"$tmp/bin/python3.14" <<'MOCK'
#!/usr/bin/env bash
if [[ $1 == -m && $2 == venv ]]; then
  destination=${@: -1}
  mkdir -p "$destination/bin"
  printf '#!/usr/bin/env bash\n' >"$destination/bin/activate"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$destination/bin/python"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$destination/bin/ansible-galaxy"
  chmod +x "$destination/bin/python" "$destination/bin/ansible-galaxy"
fi
MOCK
cat >"$tmp/bin/ansible-galaxy" <<'MOCK'
#!/usr/bin/env bash
exit 0
MOCK
chmod +x "$tmp/bin/"*
for environment in ansible-min ansible-current ansible-next; do
  PATH="$tmp/bin:$PATH" "$fixture/scripts/setup-venv" "$environment" >/dev/null
  expected=collections.yml
  [[ $environment != ansible-min ]] || expected=collections-ansible-min.yml
  (
    unset IDARSI_MOLECULE_COLLECTIONS_FILE
    # shellcheck disable=SC1090
    source "$fixture/.venv/$environment/bin/activate"
    [[ $IDARSI_ANSIBLE_ENVIRONMENT == "$environment" ]]
    [[ $IDARSI_MOLECULE_COLLECTIONS_FILE == "$expected" ]]
  )
  (
    IDARSI_MOLECULE_COLLECTIONS_FILE=user-value
    # shellcheck disable=SC1090
    source "$fixture/.venv/$environment/bin/activate"
    [[ $IDARSI_MOLECULE_COLLECTIONS_FILE == user-value ]]
  )
done
printf 'Activation hook behavior checks passed.\n'

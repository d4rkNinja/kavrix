export interface WorkspaceManifest {
  readonly name: string;
  readonly dependencies: Readonly<Record<string, string>>;
  readonly devDependencies?: Readonly<Record<string, string>>;
}

function isPackageName(value: string): boolean {
  return value.startsWith('@')
    ? /^@[^@/\\:\s]+\/[^@/\\:\s]+$/u.test(value)
    : /^[^@/\\:\s]+$/u.test(value);
}

function aliasRangeSeparator(value: string): number {
  if (!value.startsWith('@')) {
    return value.indexOf('@');
  }

  const scopeSeparator = value.indexOf('/');
  return scopeSeparator === -1 ? -1 : value.indexOf('@', scopeSeparator + 1);
}

function workspaceAliasTarget(selector: string): string | undefined {
  const separator = aliasRangeSeparator(selector);
  if (separator <= 0 || separator === selector.length - 1) {
    return undefined;
  }

  const target = selector.slice(0, separator);
  return isPackageName(target) ? target : undefined;
}

function resolveWorkspaceTarget(
  dependencyName: string,
  specifier: string,
): string | undefined {
  const selector = specifier.slice('workspace:'.length);
  const aliasTarget = workspaceAliasTarget(selector);
  if (aliasTarget !== undefined) {
    return aliasTarget;
  }

  return selector === '' || /^[*~^<>=v0-9xX]/u.test(selector)
    ? dependencyName
    : undefined;
}

function npmAliasTarget(specifier: string): string | undefined {
  const selector = specifier.slice('npm:'.length);
  const separator = aliasRangeSeparator(selector);
  const target = separator === -1 ? selector : selector.slice(0, separator);
  return isPackageName(target) ? target : undefined;
}

function dependencyTargetPath(
  path: readonly string[],
  dependencyName: string,
  targetPackage: string,
): readonly string[] {
  const dependencyPath = [...path, dependencyName];
  return dependencyName === targetPackage
    ? dependencyPath
    : [...dependencyPath, targetPackage];
}

function localDependencyDescription(specifier: string): string | undefined {
  if (specifier.startsWith('file:')) {
    return 'file: specifier';
  }
  if (specifier.startsWith('link:')) {
    return 'link: specifier';
  }
  if (/^(?:[./\\]|~[/\\]|[a-z]:)/iu.test(specifier)) {
    return 'filesystem path';
  }
  if (!specifier.includes('://') && /\.(?:tgz|tar\.gz|tar)$/iu.test(specifier)) {
    return 'local tarball';
  }
  return undefined;
}

export function reachableProductionPackages(
  manifests: readonly WorkspaceManifest[],
  rootPackage: string,
  forbiddenPackages: ReadonlySet<string>,
): ReadonlySet<string> {
  const manifestsByName = new Map<string, WorkspaceManifest>();
  for (const manifest of manifests) {
    if (manifestsByName.has(manifest.name)) {
      throw new Error(`Duplicate workspace manifest: ${manifest.name}`);
    }
    manifestsByName.set(manifest.name, manifest);
  }

  const reachable = new Set<string>();
  const visit = (packageName: string, path: readonly string[]): void => {
    if (forbiddenPackages.has(packageName)) {
      throw new Error(
        `Forbidden Kavrix production dependency path: ${path.join(' -> ')}`,
      );
    }
    if (reachable.has(packageName)) {
      return;
    }

    const manifest = manifestsByName.get(packageName);
    if (manifest === undefined) {
      throw new Error(
        `Unknown Kavrix production dependency path: ${path.join(' -> ')}`,
      );
    }

    reachable.add(packageName);
    const productionDependencies = Object.entries(manifest.dependencies).sort(
      ([left], [right]) => left.localeCompare(right),
    );
    for (const [dependencyName, specifier] of productionDependencies) {
      const dependencyPath = [...path, dependencyName];
      if (forbiddenPackages.has(dependencyName)) {
        throw new Error(
          `Forbidden Kavrix production dependency path: ${dependencyPath.join(' -> ')}`,
        );
      }

      if (specifier.startsWith('workspace:')) {
        const targetPackage = resolveWorkspaceTarget(dependencyName, specifier);
        if (targetPackage === undefined) {
          throw new Error(
            `Unresolved workspace production dependency path: ${dependencyPath.join(' -> ')} (unresolved workspace specifier)`,
          );
        }

        const targetPath = dependencyTargetPath(path, dependencyName, targetPackage);
        if (
          !manifestsByName.has(targetPackage) &&
          !forbiddenPackages.has(targetPackage)
        ) {
          throw new Error(
            `Unknown workspace production dependency path: ${targetPath.join(' -> ')}`,
          );
        }
        visit(targetPackage, targetPath);
        continue;
      }

      if (specifier.startsWith('npm:')) {
        const targetPackage = npmAliasTarget(specifier);
        if (targetPackage === undefined) {
          throw new Error(
            `Unresolved package alias production dependency path: ${dependencyPath.join(' -> ')} (npm: alias)`,
          );
        }

        const targetPath = dependencyTargetPath(path, dependencyName, targetPackage);
        if (forbiddenPackages.has(targetPackage)) {
          throw new Error(
            `Forbidden Kavrix production dependency path: ${targetPath.join(' -> ')}`,
          );
        }
        if (
          manifestsByName.has(dependencyName) ||
          dependencyName.startsWith('@kavrix/') ||
          manifestsByName.has(targetPackage) ||
          targetPackage.startsWith('@kavrix/')
        ) {
          // A registry alias can select a different version whose transitive
          // graph is not represented by the discovered workspace manifest.
          throw new Error(
            `Unresolved package alias production dependency path: ${targetPath.join(' -> ')} (npm: alias)`,
          );
        }
        continue;
      }

      const localDescription = localDependencyDescription(specifier);
      if (localDescription !== undefined) {
        throw new Error(
          `Unresolved local production dependency path: ${dependencyPath.join(' -> ')} (${localDescription})`,
        );
      }

      if (
        manifestsByName.has(dependencyName) ||
        dependencyName.startsWith('@kavrix/')
      ) {
        visit(dependencyName, dependencyPath);
      }
    }
  };

  visit(rootPackage, [rootPackage]);
  return reachable;
}

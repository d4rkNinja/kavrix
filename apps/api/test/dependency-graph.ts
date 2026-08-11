export interface WorkspaceManifest {
  readonly name: string;
  readonly dependencies: Readonly<Record<string, string>>;
  readonly devDependencies?: Readonly<Record<string, string>>;
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
    const workspaceDependencies = Object.keys(manifest.dependencies)
      .filter(
        (dependency) =>
          manifestsByName.has(dependency) || dependency.startsWith('@kavrix/'),
      )
      .sort();
    for (const dependency of workspaceDependencies) {
      visit(dependency, [...path, dependency]);
    }
  };

  visit(rootPackage, [rootPackage]);
  return reachable;
}

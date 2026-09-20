/** Default public product label. Callers may override; never hard-code a rename. */
export const DEFAULT_PRODUCT_LABEL = 'CredVault';

/** Default public executable name. Callers may override. */
export const DEFAULT_EXECUTABLE_NAME = 'creds';

export interface ProductIdentity {
  readonly productLabel: string;
  readonly executableName: string;
}

/**
 * Resolves the configurable product label and executable. Empty overrides
 * fall back to CredVault / creds.
 */
export function resolveProductIdentity(
  options: Readonly<{
    productLabel?: string;
    executableName?: string;
  }> = {},
): ProductIdentity {
  const productLabel = options.productLabel?.trim();
  const executableName = options.executableName?.trim();
  return {
    productLabel:
      productLabel === undefined || productLabel.length === 0
        ? DEFAULT_PRODUCT_LABEL
        : productLabel,
    executableName:
      executableName === undefined || executableName.length === 0
        ? DEFAULT_EXECUTABLE_NAME
        : executableName,
  };
}

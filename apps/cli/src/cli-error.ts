/**
 * Leaf failure type shared by every CLI layer. Domain modules raise this
 * instead of leaking raw internals upward; the top-level runner recognizes it
 * by name so reviewed messages always reach the user unchanged.
 */
export class LocalCliError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'LocalCliError';
  }
}

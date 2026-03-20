# protonmeet-identifiers

See [mimi-protocol](https://www.ietf.org/archive/id/draft-ietf-mimi-protocol-00.html#table-1)

| name            | format                                                    | example                                                                      | about                     |
|-----------------|-----------------------------------------------------------|------------------------------------------------------------------------------|---------------------------|
| user-id         | `mimi://{domain}/u/{rand-id}`                             | `mimi://proton.me/u/01J0TTK9PV36EYE2PTV5SJPE56`                              | a human user              |
| device-id       | `{user-id}/d/{rand-id}`                                   | `mimi://proton.me/u/01J0TTK9PV36EYE2PTV5SJPE56/d/01J0TTM454GQN06RWH0WD5ZPAR` | a device                  |
| room-id         | `mimi://{domain}/r/{rand-id}`                             | `mimi://proton.me/r/01J0TT9XHCH1ZJGYWJ8MSCZQKT`                              | a MLS group               |
| commit-msg-id   | `{room-id}/c/{epoch}`                                     | `mimi://proton.me/r/01J0TT9XHCH1ZJGYWJ8MSCZQKT/c/42`                         | CommitMessage             |
| app-msg-id      | `{prev-commit-msg-id}/m/{sender-leaf-index}/{generation}` | `mimi://proton.me/r/01J0TT9XHCH1ZJGYWJ8MSCZQKT/c/42/m/1/5`                   | ApplicationMessage        |
| proposal-msg-id | `{commit-msg-id}/p/{proposal-ref}`                        | `mimi://proton.me/r/01J0TT9XHCH1ZJGYWJ8MSCZQKT/c/42/p/0845106e[..]`          | ProposalMessage           |

## Example

```rust
use meet_identifiers::*;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {

    let mut rng = rand::thread_rng();
    let protonme = "proton.me".parse()?;

    let john_doe = UserId::new_random(&mut rng, &protonme);

    let john_doe_ios = DeviceId::new_random(&mut rng, &john_doe);
    let john_doe_android = DeviceId::new_random(&mut rng, &john_doe);

    let room = RoomId::new_random(&mut rng, &protonme);

    // let commit = CommitId::new();

    Ok(())
}
```

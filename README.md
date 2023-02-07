<p align="center">
  <img
    src="https://github.com/AfricaN3/LifeSaver-Contracts/blob/master/media/mascot.png"
    width="200px;"></img>
</p>

<h1 align="center">LifeSaver NFTs</h1>

<p align="center">
  The LifeSaver (LIFE) NFTs are Soulbound tokens of the NEP-11 standard given to blood drive participants. 
  <br/> Made with ❤ by <b>AfricaN3.com</b>
</p>

## Features

- Regular token transfers are disallowed.
- Each NFT will belong to an `era`. Every blood drive event starts a new `era`.
- An `era` can only start when 100 $GAS (this will be an adjustable parameter) is deposited to the contract (minimum raffle reward pool).
- There are 3 LIFE `archetypes` for every `era`:
  1. **_donor_** given to blood donors during the blood drive.
  2. **_angel_** given to LIFE minters during an `era`, The minting fee is set by `era admin`. All of the fee is added to the raffle reward pool.
  3. **_fan_** limited NFT given to the barmy army of an era.
- Only `era admin` (blood drive organization) can mint LIFE of the **_donor_** `archetype` to an address.
- The number of raffle winners will be set by the `era admin`.
- Special token transfers called `rescues` are allowed for ~1 hour when the NFT owner can provide proof to the `era admin` that both the `from` and `to` wallet belong to them.
- Only allows a maximum balance of one per `era` for every address.

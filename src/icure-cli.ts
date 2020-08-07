import fetch from 'node-fetch'
import {
	ContactDto,
	Filter, HealthcarePartyDto,
	ImportResultDto,
	ListOfIdsDto,
	MedicationSchemeExportInfoDto,
	PatientDto,
	UserDto
} from 'icc-api'
import { chunk, flatMap, get, assign, omit, default as _ } from 'lodash'
import { Api } from './api'

import * as colors from 'colors/safe'
import { Args, CommandInstance } from 'vorpal'
import StatusEnum = UserDto.StatusEnum
import TypeEnum = UserDto.TypeEnum

require('node-json-color-stringify')

const path = require('path')
const fs = require('fs')
const vorpal = new (require('vorpal'))()

// TODO use a logger
// TODO patient merges
// TODO more examples, with invoices/health elements/contacts, at first level

const tmp = require('os').tmpdir()
console.log('Tmp dir: ' + tmp)
;(global as any).localStorage = new (require('node-localstorage').LocalStorage)(tmp, 5 * 1024 * 1024 * 1024)
;(global as any).Storage = ''

const options = {
	username: 'abdemo',
	password: 'knalou',
	host: 'https://backendb.svc.icure.cloud/rest/v1',
	repoUsername: null,
	repoPassword: null,
	repoHost: null,
	repoHeader: {}
}

let api = new Api(options.host, { Authorization: `Basic ${Buffer.from(`${options.username}:${options.password}`).toString('base64')}` }, fetch as any)
let latestImport: ImportResultDto
let latestExport: ArrayBufferLike

vorpal
	.command('login <username> <password> [host]', 'Login to iCure')
	.action(async function(this: CommandInstance, args: Args) {
		options.username = args.username
		options.password = args.password
		args.host && (options.host = args.host)

		api = new Api(options.host, { Authorization: `Basic ${Buffer.from(`${options.username}:${options.password}`).toString('base64')}` }, fetch as any)
	})

vorpal
	.command('pki <hcpId> <key>', 'Private Key Import')
	.action(async function(this: CommandInstance, args: Args) {
		const hcpId = args.hcpId
		const key = args.key

		await api.cryptoicc.loadKeyPairsAsTextInBrowserLocalStorage(hcpId, api.cryptoicc.utils.hex2ua(key))
		if (await api.cryptoicc.checkPrivateKeyValidity(await api.hcpartyicc.getHealthcareParty(hcpId))) {
			this.log('Key is valid')
		} else {
			this.log('Key is invalid')
		}
	})

vorpal
	.command('lpkis', 'List Private Keys')
	.action(async function(this: CommandInstance, args: Args) {
		const users = (await api.usericc.listUsers(undefined, undefined, undefined)).rows
		users.reduce(async (p: Promise<any>, u: UserDto) => {
			await p
			if (u.healthcarePartyId) {
				const hcp = await api.hcpartyicc.getHealthcareParty(u.healthcarePartyId)
				try {
					if (hcp.publicKey && await api.cryptoicc.checkPrivateKeyValidity(hcp)) {
						this.log(`${colors.green('√')} ${hcp.id}: ${hcp.firstName} ${hcp.lastName}`)
					} else {
						this.log(`${colors.red('X')} ${hcp.id}: ${hcp.firstName} ${hcp.lastName}`)
					}
				} catch (e) {
					this.log(`X ${hcp.id}: ${hcp.firstName} ${hcp.lastName}`)
				}
			}
		}, Promise.resolve())
	})

vorpal
	.command('whoami', 'Logged user info')
	.action(async function(this: CommandInstance, args: Args) {
		this.log((await api.usericc.getCurrentUser()).login + '@' + options.host)
	})

vorpal
	.command('pat [name] [first]', 'Logged user info')
	.action(async function(this: CommandInstance, args: Args) {
		this.log(JSON.stringify((await api.patienticc.fuzzySearchWithUser(await api.usericc.getCurrentUser(), args.first, args.name, undefined))
			.map((p: PatientDto) => ({ id: p.id, lastName: p.lastName, firstName: p.firstName }))))
	})

vorpal
	.command('missingdel <entity> [hcpIds...]', 'Get list of mismatch access on list of hcp id')
	.action(async function(this: CommandInstance, args: Args) {
		const all = {}
		const byHcp = {} as any
		let user = await api.usericc.getCurrentUser()

		await Promise.all(args.hcpIds.map(async (hcpId: string) => {
			const batchIds = await api.contacticc.matchBy(new Filter({
				healthcarePartyId: hcpId,
				$type: 'ContactByHcPartyTagCodeDateFilter'
			}))
			const batch = batchIds
				.reduce((acc: { [key: string]: number }, id: string) => {
					acc[id] = 1
					return acc
				}, {})
			byHcp[hcpId] = batch
			Object.assign(all, batch)
		}))

		const incomplete = Object.keys(all).filter(id => Object.keys(byHcp).some(k => !byHcp[k][id]))

		const patIds = await contactsToPatientIds(user.healthcarePartyId, await api.contacticc.getContactsWithUser(user, new ListOfIdsDto({ ids: incomplete })))

		this.log(JSON.stringify(patIds))
	})

vorpal
	.command('share <hcpId> [patIds...]', 'Share with hcp ids')
	.action(async function(this: CommandInstance, args: Args) {
		let user = await api.usericc.getCurrentUser()

		const hcpId = args.hcpId
		const ids = args.patIds

		const patients = await api.patienticc.getPatientsWithUser(user, new ListOfIdsDto({ ids })) // Get them to fix them

		this.log(JSON.stringify((await patients.reduce(async (p: Promise<any>, pat: PatientDto) => {
			const prev = await p
			try {
				return prev.concat([await api.patienticc.share(user, pat.id!, user.healthcarePartyId!, [hcpId], { [hcpId]: ['all'] })])
			} catch (e) {
				console.log(e)
				return prev
			}
		}
			, Promise.resolve([]))).map((x: any) => x.statuses), undefined, ' '))
	})

vorpal
	.command('shareall [hcpIds...]', 'Share with hcp ids')
	.action(async function(this: CommandInstance, args: Args) {
		let user = await api.usericc.getCurrentUser()

		const hcpIds = args.hcpIds as string[]
		const allIds = await api.patienticc.listPatientsIds(user.healthcarePartyId, undefined, undefined, 20000)

		chunk(allIds.rows, 100).reduce(async (p, ids) => {
			await p
			const patients = await api.patienticc.getPatientsWithUser(user, new ListOfIdsDto({ ids })) // Get them to fix them

			this.log(JSON.stringify((await patients.reduce(async (p: Promise<any>, pat: PatientDto) => {
				const prev = await p
				try {
					return prev.concat([await api.patienticc.share(user, pat.id!, user.healthcarePartyId!, hcpIds, hcpIds.reduce((map,hcpId) => Object.assign(map, { [hcpId]: ['all'] }), {}))])
				} catch (e) {
					console.log(e)
					return prev
				}
			}
				, Promise.resolve([]))).map((x: any) => x.statuses), undefined, ' '))

		}, Promise.resolve())

	})

vorpal
	.command('imp-ms [path]', 'Convert local medication scheme xml to services')
	.action(async function(this: CommandInstance, args: Args) {
		const user = await api.usericc.getCurrentUser()
		const doc = await api.documenticc.createDocument({
			id: api.cryptoicc.randomUuid(),
			author: user.id,
			responsible: user.healthcarePartyId
		})
		await api.documenticc.setAttachment(doc.id, undefined, fs.readFileSync(args.path).buffer)
		latestImport = (await api.bekmehricc.importMedicationScheme(doc.id, undefined, true, undefined, 'fr', {}))[0]
		this.log(JSON.stringify(latestImport))
	})

vorpal
	.command('exp-ms', 'Export medication scheme from latest import to xml')
	.action(async function(this: CommandInstance, args: Args) {
		latestExport = await api.bekmehricc.generateMedicationSchemeExport(latestImport.patient!.id!, 'fr', undefined, new MedicationSchemeExportInfoDto({
			services: flatMap(latestImport.ctcs!.map(c => c.services))
		}))
		this.log(api.cryptoicc.utils.ua2utf8(latestExport))
	})

vorpal
	.command('createUser <firstName> <lastName> <email> [ssin] [nihii] [parentId]', 'This function create user in db. firstName, lastName and email are mandatory. Ssin, nihii and parent id are optional')
	.action(async function(this: CommandInstance, args: Args) {
		this.log('FirstName: ' + args.firstName + ' LastName: ' + args.lastName + ' Email: ' + args.email + ' Ssin' + args.ssin + ' Nihii: ' + args.nihii + ' ParentId: ' + args.parentId)
		let hcp = await api.hcpartyicc.createHealthcareParty({
			name: get(args, 'firstName', null) + ' ' + get(args, 'lastName', null),
			lastName: get(args, 'lastName', null),
			firstName: get(args, 'firstName', null),
			nihii: get(args, 'nihii', ''),
			ssin: get(args, 'ssin', ''),
			parentId: get(args, 'parentId', null)
		})
		let delegations = {
			all: [hcp.id]
		}
		if (args.delegationTypeForParent === 'all') {
			delegations.all.push(hcp.parentId)
		}
		let user = await api.usericc.createUser({
			healthcarePartyId: hcp.id,
			name: get(args, 'firstName', null) + ' ' + get(args, 'lastName', null),
			email: get(args, 'email', null),
			applicationTokens: { tmpFirstLogin: api.cryptoicc.randomUuid() },
			status: StatusEnum.ACTIVE,
			type: TypeEnum.Database,
			autoDelegations: delegations
		})
		this.log('UserId: ' + user.id + ' Token: ' + user.applicationTokens.tmpFirstLogin)
	})

vorpal
	.command('restoreCrypto <currentKey> <originalKey>', 'Restore crypto in all docs for hcp who have changed its hcpartykey. Parameters: currentKey, originalKey')
	.action(async function(this: CommandInstance, args: Args) {
		const currentKey = args.currentKey
		const originalKey = args.originalKey

		const user = await api.usericc.getCurrentUser()
		const currentHcp = await api.hcpartyicc.getHealthcareParty(user.healthcarePartyId)
		const originalHcp = assign(omit(currentHcp, ['hcPartyKeys']), {
			'hcPartyKeys': {
				'773abf12-9227-4015-babf-129227a015c4': [
					'71cdfa834b4c4f3e067de9223e670737ba23b62632e7180c80bb12289a434641e43b73bc252eb116458434ecda736cf9488f6fd500b7476764f190f0e89c5c5fa0026058bd63921e24a57348a739af59e68853cef8049c91ee431fc15dc0ad933f2d191c1d029aafc2070fcba2d37f74bcbbdcc4b4b26789e5d7ec2b37eb95a14fb76b163a19ec6d77fd236afb79127ba4eca0cbf48b3b8de0d3a49704063b92468df8fae96177b58f7cfee35d182f91b185a83359e6b292c7e871137ede5f2e5c9ac2388788127b6627431f5433a3c3d0b3a17be23f53b06b196dd084cc3cded2b63b285d0a38eae3b28f05a213aa7a0c44be87747ed093c6c5a59472284a0b',
					'71cdfa834b4c4f3e067de9223e670737ba23b62632e7180c80bb12289a434641e43b73bc252eb116458434ecda736cf9488f6fd500b7476764f190f0e89c5c5fa0026058bd63921e24a57348a739af59e68853cef8049c91ee431fc15dc0ad933f2d191c1d029aafc2070fcba2d37f74bcbbdcc4b4b26789e5d7ec2b37eb95a14fb76b163a19ec6d77fd236afb79127ba4eca0cbf48b3b8de0d3a49704063b92468df8fae96177b58f7cfee35d182f91b185a83359e6b292c7e871137ede5f2e5c9ac2388788127b6627431f5433a3c3d0b3a17be23f53b06b196dd084cc3cded2b63b285d0a38eae3b28f05a213aa7a0c44be87747ed093c6c5a59472284a0b'
				],
				'3ea0ffec-b126-46ab-a0ff-ecb12626ab5b': [
					'4e79970cc98edcff9b3930aeca84dab205613206046ce23874dd0c3290b47c6eee61cbb8f43a31449ca84bc721af7a2e918db7d56f035987a68657a316bf0bd861c92c626d58a2c9338958e3a4b1877b9023f629afc209deb6b5c03d46e54c782ddc88498e8e88017ce4b8f30791780df0b47745e05cc75f85388b6a87c02eccd7babd9d7d12132212f40e7bdf72adaa158717b0af90bb7e59a931151b03cdb80b10a2874eb628daf13cff11ad9d6ae20db2b87b36257679ee147f4816b08663fb10120450cc6b96fe43c636ca02f6d90a6f57d2c8f139128459c9639c0ff543d5c061c7ab2e40b7e0c28ecb27045175e530db51d8b7d92e872b3b3025943b2b',
					'341609b60919c7be3bd4821f31c43bf8a5a7adfdbfe78893844864468285f7f0bf94978a36614bfbd5180b57405e689555bc9a3bce4e4e2dd7dfc139586000daa7812d7710b8ca89c93996b08c425fe09d2a1d3f8836c02d45e6197213ccaf1d4d13b08017e5270f049fe07a5a4ab3e508f257f3f7c5f7e03b682471078a52126037dbe6ed380440bd0ae3eaa3e69ab00bf50594e430d42ee404306a8ef3987fafcf072a8004d92cf29cc188ae3e7ec79862abe39c3709b390229faaceb7275045a1c523c799570f890c9f2c2803c0cdb4369403a03cd4011d6aea0a1b986ffa382aca66fdabc158c90d8a7e901d7564152b6fa292ca8fc31e2f4a52e6d66356'
				]
			}
		})

		await api.cryptoicc.loadKeyPairsAsTextInBrowserLocalStorage(get(currentHcp, 'id', null), api.cryptoicc.utils.hex2ua(currentKey))
		await api.cryptoicc.checkPrivateKeyValidity(currentHcp) ? this.log(`${colors.green('√')} Current key is valid`) : this.log(`${colors.red('X')} Current key is invalid`)

		await api.cryptoicc.loadKeyPairsAsTextInBrowserLocalStorage(get(originalHcp, 'id', null), api.cryptoicc.utils.hex2ua(originalKey))
		await api.cryptoicc.checkPrivateKeyValidity(originalHcp) ? this.log(`${colors.green('√')} Original key is valid`) : this.log(`${colors.red('X')} Original key is invalid`)

		const allIds = await api.patienticc.listPatientsIds(user.healthcarePartyId, undefined, undefined, 20000)

		chunk(allIds.rows, 100).reduce(async (p, ids) => {
			await p
			const patients = await api.patienticc.getPatientsWithUser(user, new ListOfIdsDto({ ids }))
		}, Promise.resolve())

	})

vorpal
	.delimiter('icure-cli$')
	.history('icrprt')
	.show()

async function contactsToPatientIds(hcpartyId: string, contacts: ContactDto[]): Promise<string[]> {
	try {
		const extractPromises = contacts.map((ctc: ContactDto) => {
			return api.cryptoicc.extractKeysFromDelegationsForHcpHierarchy(hcpartyId, ctc.id || '', ctc.cryptedForeignKeys || {}).catch(() => ({ extractedKeys: [] }))
		})
		const extracted = await Promise.all(extractPromises)
		return [...new Set(flatMap(extracted, it => it.extractedKeys))]
	} catch (error) {
		console.error('Error while converting contacts to patient ids')
		console.error(error)
		return Promise.reject()
	}
}
